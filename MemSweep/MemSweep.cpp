/* Memory enumerator
   https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing
   Forrest Orr - 2019
   forrest.orr@protonmail.com
   Licensed under GNU GPLv3 */

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <list>
#ifdef _WIN64
#pragma pack(push, 8) // Bug fix for strange x64 bug, sizeof PROCESSENTRY struct in 64-bit is unaligned and will break Process32First, with error code ERROR_BAD_LENGTH
#include <Tlhelp32.h>
#pragma pack(pop)
#else
#include <Tlhelp32.h>
#endif

using namespace std;

list<MEMORY_BASIC_INFORMATION*> QueryProcessMem(uint32_t dwPid) {
	list<MEMORY_BASIC_INFORMATION*> ProcessMem;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, dwPid);

	if (hProcess != nullptr) {
		MEMORY_BASIC_INFORMATION* pMemInfo = nullptr;

		for (uint8_t* p = nullptr;; p += pMemInfo->RegionSize) {
			pMemInfo = new MEMORY_BASIC_INFORMATION;

			if (VirtualQueryEx(hProcess, p, pMemInfo, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION)) {
				ProcessMem.push_back(pMemInfo);
			}
			else {
				delete pMemInfo;
				break;
			}
		}

		CloseHandle(hProcess);
	}

	return ProcessMem;
}

void EnumProcessMem(uint32_t dwTargetPid, uint8_t* pBaseAddress = (uint8_t*)0x00400000) {
	list<MEMORY_BASIC_INFORMATION*> ProcessMem = QueryProcessMem(dwTargetPid);

	for (list<MEMORY_BASIC_INFORMATION*>::const_iterator i = ProcessMem.begin(); i != ProcessMem.end(); ++i) {
		if (pBaseAddress == (uint8_t*)-1 || (*i)->AllocationBase == (void*)pBaseAddress) {
			printf(
				"0x%p\r\n"
				"  Base: 0x%p\r\n"
				"  Size: %d\r\n",
				(*i)->AllocationBase,
				(*i)->BaseAddress,
				(*i)->RegionSize);

			printf("  State: ");
			switch ((*i)->State)
			{
			case MEM_COMMIT:
				printf("MEM_COMMIT\r\n");
				break;
			case MEM_RESERVE:
				printf("MEM_RESERVE\r\n");
				break;
			case MEM_FREE:
				printf("MEM_FREE\r\n");
				break;
			default:
				printf("Invalid?\r\n");
			}

			printf("  Type: ");
			switch ((*i)->Type)
			{
			case MEM_IMAGE:
				printf("MEM_IMAGE\r\n");
				break;
			case MEM_MAPPED:
				printf("MEM_MAPPED\r\n");
				break;
			case MEM_PRIVATE:
				printf("MEM_PRIVATE\r\n");
				break;
			default:
				printf("Invalid?\r\n");
			}

			printf("  Current permissions: 0x%08x\r\n", (*i)->Protect);
			printf("  Original permissions: 0x%08x\r\n", (*i)->AllocationProtect);
		}
	}
}

int32_t wmain(int32_t nArgc, const wchar_t* pArgv[]) {
	if (nArgc < 3) {
		printf("* Usage: %ws [PID \"current\" or \"all\" to scan all processes] [\"enum\" to output details or \"stats\" to give statistics]\r\n", pArgv[0]);
	}
	else {
		bool bScanAll = false, bStats = false;
		uint32_t dwPid = GetCurrentProcessId();

		if (_wcsicmp(pArgv[1], L"all") == 0) {
			bScanAll = true;
		}
		else if (_wcsicmp(pArgv[1], L"current") != 0) {
			dwPid = _wtoi(pArgv[1]);
		}
		if (_wcsicmp(pArgv[2], L"stats") == 0) {
			bStats = true;
		}

		if (!bScanAll) {
			if (!bStats) {
				EnumProcessMem(dwPid, (uint8_t*)-1);
			}
			else {
				//
			}
		}
		else {
			PROCESSENTRY32W ProcEntry = { 0 };
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			list<MEMORY_BASIC_INFORMATION*> ImageMem, MapMem, PrivateMem;

			if (hSnapshot != nullptr)
			{
				ProcEntry.dwSize = sizeof(PROCESSENTRY32W);

				if (Process32FirstW(hSnapshot, &ProcEntry))
				{
					do
					{
						if (!bStats) {
							EnumProcessMem(ProcEntry.th32ProcessID, (uint8_t*)-1);
						}
						else {
							list<MEMORY_BASIC_INFORMATION*> ProcessMem = QueryProcessMem(ProcEntry.th32ProcessID);

							for (list<MEMORY_BASIC_INFORMATION*>::const_iterator i = ProcessMem.begin(); i != ProcessMem.end(); ++i) {
								if ((*i)->Type == MEM_IMAGE) {
									ImageMem.push_back(*i);
								}
								else if ((*i)->Type == MEM_MAPPED) {
									MapMem.push_back(*i);
								}
								else if ((*i)->Type == MEM_PRIVATE) {
									PrivateMem.push_back(*i);
								}
							}
						}
					} while (Process32NextW(hSnapshot, &ProcEntry));
				}

				CloseHandle(hSnapshot);
			}
			else
			{
				printf("- Failed to create process list snapshot (error %d)\r\n", GetLastError());
			}

			list<MEMORY_BASIC_INFORMATION*> Readonly, ReadWrite, ReadExec, ReadWriteExec, ExecWriteCopy, WriteCopy, Exec;

			for (list<MEMORY_BASIC_INFORMATION*>::const_iterator i = ImageMem.begin(); i != ImageMem.end(); ++i) {
				switch ((*i)->Protect) {
				case PAGE_READONLY:
					Readonly.push_back(*i);
					break;
				case PAGE_READWRITE:
					ReadWrite.push_back(*i);
					break;
				case PAGE_EXECUTE_READ:
					ReadExec.push_back(*i);
					break;
				case PAGE_EXECUTE_READWRITE:
					ReadWriteExec.push_back(*i);
					break;
				case PAGE_EXECUTE_WRITECOPY:
					ExecWriteCopy.push_back(*i);
					break;
				case PAGE_WRITECOPY:
					WriteCopy.push_back(*i);
					break;
				case PAGE_EXECUTE:
					Exec.push_back(*i);
					break;
				default: break;
				}
			}

			printf("~ Image memory (%d total):\r\n", ImageMem.size());
			printf("  PAGE_READONLY: %d (%f%%)\r\n", Readonly.size(), (float)Readonly.size() / ImageMem.size() * 100.0);
			printf("  PAGE_READWRITE: %d (%f%%)\r\n", ReadWrite.size(), (float)ReadWrite.size() / ImageMem.size() * 100.0);
			printf("  PAGE_EXECUTE_READ: %d (%f%%)\r\n", ReadExec.size(), (float)ReadExec.size() / ImageMem.size() * 100.0);
			printf("  PAGE_EXECUTE_READWRITE: %d (%f%%)\r\n", ReadWriteExec.size(), (float)ReadWriteExec.size() / ImageMem.size() * 100.0);
			printf("  PAGE_EXECUTE_WRITECOPY: %d (%f%%)\r\n", ExecWriteCopy.size(), (float)ExecWriteCopy.size() / ImageMem.size() * 100.0);
			printf("  PAGE_WRITECOPY: %d (%f%%)\r\n", WriteCopy.size(), (float)WriteCopy.size() / ImageMem.size() * 100.0);
			printf("  PAGE_EXECUTE: %d (%f%%)\r\n", Exec.size(), (float)Exec.size() / ImageMem.size() * 100.0);

			Readonly.clear();
			ReadWrite.clear();
			ReadExec.clear();
			ReadWriteExec.clear();
			ExecWriteCopy.clear();
			WriteCopy.clear();
			Exec.clear();

			for (list<MEMORY_BASIC_INFORMATION*>::const_iterator i = MapMem.begin(); i != MapMem.end(); ++i) {
				switch ((*i)->Protect) {
				case PAGE_READONLY:
					Readonly.push_back(*i);
					break;
				case PAGE_READWRITE:
					ReadWrite.push_back(*i);
					break;
				case PAGE_EXECUTE_READ:
					ReadExec.push_back(*i);
					break;
				case PAGE_EXECUTE_READWRITE:
					ReadWriteExec.push_back(*i);
					break;
				case PAGE_EXECUTE_WRITECOPY:
					ExecWriteCopy.push_back(*i);
					break;
				case PAGE_WRITECOPY:
					WriteCopy.push_back(*i);
					break;
				case PAGE_EXECUTE:
					Exec.push_back(*i);
					break;
				default: break;
				}
			}

			printf("~ Mapped memory (%d total):\r\n", MapMem.size());
			printf("  PAGE_READONLY: %d (%f%%)\r\n", Readonly.size(), (float)Readonly.size() / MapMem.size() * 100.0);
			printf("  PAGE_READWRITE: %d (%f%%)\r\n", ReadWrite.size(), (float)ReadWrite.size() / MapMem.size() * 100.0);
			printf("  PAGE_EXECUTE_READ: %d (%f%%)\r\n", ReadExec.size(), (float)ReadExec.size() / MapMem.size() * 100.0);
			printf("  PAGE_EXECUTE_READWRITE: %d (%f%%)\r\n", ReadWriteExec.size(), (float)ReadWriteExec.size() / MapMem.size() * 100.0);
			printf("  PAGE_EXECUTE_WRITECOPY: %d (%f%%)\r\n", ExecWriteCopy.size(), (float)ExecWriteCopy.size() / MapMem.size() * 100.0);
			printf("  PAGE_WRITECOPY: %d (%f%%)\r\n", WriteCopy.size(), (float)WriteCopy.size() / MapMem.size() * 100.0);
			printf("  PAGE_EXECUTE: %d (%f%%)\r\n", Exec.size(), (float)Exec.size() / MapMem.size() * 100.0);

			Readonly.clear();
			ReadWrite.clear();
			ReadExec.clear();
			ReadWriteExec.clear();
			ExecWriteCopy.clear();
			WriteCopy.clear();
			Exec.clear();

			for (list<MEMORY_BASIC_INFORMATION*>::const_iterator i = PrivateMem.begin(); i != PrivateMem.end(); ++i) {
				switch ((*i)->Protect) {
				case PAGE_READONLY:
					Readonly.push_back(*i);
					break;
				case PAGE_READWRITE:
					ReadWrite.push_back(*i);
					break;
				case PAGE_EXECUTE_READ:
					ReadExec.push_back(*i);
					break;
				case PAGE_EXECUTE_READWRITE:
					ReadWriteExec.push_back(*i);
					break;
				case PAGE_EXECUTE_WRITECOPY:
					ExecWriteCopy.push_back(*i);
					break;
				case PAGE_WRITECOPY:
					WriteCopy.push_back(*i);
					break;
				case PAGE_EXECUTE:
					Exec.push_back(*i);
					break;
				default: break;
				}
			}

			printf("~ Private memory (%d total):\r\n", PrivateMem.size());
			printf("  PAGE_READONLY: %d (%f%%)\r\n", Readonly.size(), (float)Readonly.size() / PrivateMem.size() * 100.0);
			printf("  PAGE_READWRITE: %d (%f%%)\r\n", ReadWrite.size(), (float)ReadWrite.size() / PrivateMem.size() * 100.0);
			printf("  PAGE_EXECUTE_READ: %d (%f%%)\r\n", ReadExec.size(), (float)ReadExec.size() / PrivateMem.size() * 100.0);
			printf("  PAGE_EXECUTE_READWRITE: %d (%f%%)\r\n", ReadWriteExec.size(), (float)ReadWriteExec.size() / PrivateMem.size() * 100.0);
			printf("  PAGE_EXECUTE_WRITECOPY: %d (%f%%)\r\n", ExecWriteCopy.size(), (float)ExecWriteCopy.size() / PrivateMem.size() * 100.0);
			printf("  PAGE_WRITECOPY: %d (%f%%)\r\n", WriteCopy.size(), (float)WriteCopy.size() / PrivateMem.size() * 100.0);
			printf("  PAGE_EXECUTE: %d (%f%%)\r\n", Exec.size(), (float)Exec.size() / PrivateMem.size() * 100.0);
		}
	}
}