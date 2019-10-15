/* Memory enumerator
   https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing
   Forrest Orr - 2019
   forrest.orr@protonmail.com
   Licensed under GNU GPLv3 */

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <list>
#include <map>
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

	for (list<MEMORY_BASIC_INFORMATION*>::const_iterator RecordItr = ProcessMem.begin(); RecordItr != ProcessMem.end(); ++RecordItr) {
		if (pBaseAddress == (uint8_t*)-1 || (*RecordItr)->AllocationBase == (void*)pBaseAddress) {
			printf(
				"* Allocated base 0x%p\r\n"
				"  Base: 0x%p\r\n"
				"  Size: %d\r\n",
				(*RecordItr)->AllocationBase,
				(*RecordItr)->BaseAddress,
				(*RecordItr)->RegionSize);

			printf("  State: ");
			switch ((*RecordItr)->State)
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
				printf("?\r\n");
			}

			printf("  Type: ");
			switch ((*RecordItr)->Type)
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
				printf("N/A\r\n");
			}

			printf("  Current permissions: 0x%08x\r\n", (*RecordItr)->Protect);
			printf("  Original permissions: 0x%08x\r\n", (*RecordItr)->AllocationProtect);
		}
	}
}

class MemoryPermissionRecord { // Record takes list of mem basic info structs, and sorts them into a map. Class can be used to show the map.
protected:
	map<uint32_t, map<uint32_t, uint32_t>>* MemPermMap; // Primary key is the memory type, secondary map key is the permission attribute (and its pair value is the count).

public:
	void UpdateMap(list<MEMORY_BASIC_INFORMATION*> MemBasicRecords) {
		for (list<MEMORY_BASIC_INFORMATION*>::const_iterator RecordItr = MemBasicRecords.begin(); RecordItr != MemBasicRecords.end(); ++RecordItr) {
			if (!MemPermMap->count((*RecordItr)->Type)) {
				MemPermMap->insert(make_pair((*RecordItr)->Type, map<uint32_t, uint32_t>()));
			}

			map<uint32_t, uint32_t>& CountMap = MemPermMap->at((*RecordItr)->Type);

			if (!CountMap.count((*RecordItr)->Protect)) {
				CountMap.insert(make_pair((*RecordItr)->Protect, 0));
			}

			CountMap[(*RecordItr)->Protect]++;
		}
	}

	~MemoryPermissionRecord() {
		//
	}

	MemoryPermissionRecord(list<MEMORY_BASIC_INFORMATION*> MemBasicRecords) {
		MemPermMap = new map<uint32_t, map<uint32_t, uint32_t>>();
		UpdateMap(MemBasicRecords);
	}

	void ShowRecords() {
		for (map<uint32_t, map<uint32_t, uint32_t>>::const_iterator Itr = MemPermMap->begin(); Itr != MemPermMap->end(); ++Itr) {
			switch (Itr->first) {
			case MEM_IMAGE:
				printf("~ Image memory:\r\n");
				break;
			case MEM_MAPPED:
				printf("~ Mapped memory:\r\n");
				break;
			case MEM_PRIVATE:
				printf("~ Private memory:\r\n");
				break;
			default:
				printf("~ Unknown memory (type 0x%08x):\r\n", Itr->first);
				break;
			}

			int32_t nTotalRegions = 0;

			for (map<uint32_t, uint32_t>::const_iterator Itr2 = Itr->second.begin(); Itr2 != Itr->second.end(); ++Itr2) {
				nTotalRegions += Itr2->second;
			}

			printf("  Total: %d\r\n", nTotalRegions);

			for (map<uint32_t, uint32_t>::const_iterator Itr2 = Itr->second.begin(); Itr2 != Itr->second.end(); ++Itr2) {
				switch (Itr2->first) {
				case PAGE_READONLY:
					printf("  PAGE_READONLY: %d (%f%%)\r\n", Itr2->second, (float)Itr2->second / nTotalRegions * 100.0);
					break;
				case PAGE_READWRITE:
					printf("  PAGE_READWRITE: %d (%f%%)\r\n", Itr2->second, (float)Itr2->second / nTotalRegions * 100.0);
					break;
				case PAGE_EXECUTE_READ:
					printf("  PAGE_EXECUTE_READ: %d (%f%%)\r\n", Itr2->second, (float)Itr2->second / nTotalRegions * 100.0);
					break;
				case PAGE_EXECUTE_READWRITE:
					printf("  PAGE_EXECUTE_READWRITE: %d (%f%%)\r\n", Itr2->second, (float)Itr2->second / nTotalRegions * 100.0);
					break;
				case PAGE_EXECUTE_WRITECOPY:
					printf("  PAGE_EXECUTE_WRITECOPY: %d (%f%%)\r\n", Itr2->second, (float)Itr2->second / nTotalRegions * 100.0);
					break;
				case PAGE_WRITECOPY:
					printf("  PAGE_WRITECOPY: %d (%f%%)\r\n", Itr2->second, (float)Itr2->second / nTotalRegions * 100.0);
					break;
				case PAGE_EXECUTE:
					printf("  PAGE_EXECUTE: %d (%f%%)\r\n", Itr2->second, (float)Itr2->second / nTotalRegions * 100.0);
					break;
				case PAGE_NOACCESS:
					printf("  PAGE_NOACCESS: %d (%f%%)\r\n", Itr2->second, (float)Itr2->second / nTotalRegions * 100.0);
					break;
				default:
					printf("  0x%08x: %d (%f%%)\r\n", Itr2->first, Itr2->second, (float)Itr2->second / nTotalRegions * 100.0);
					break;
				}
			}
		}
	}
};

enum class SelectedProcessType {
	InvalidPid = 0,
	SpecificPid,
	AllPids,
	SelfPid
};

enum class SelectedOutputType {
	InvalidOutput = 0,
	Raw,
	Statistics
};

int32_t wmain(int32_t nArgc, const wchar_t* pArgv[]) {
	if (nArgc < 5) {
		printf("* Usage: %ws --target (PID) --output-type (see remarks) --base-address (scans only the memory in the region address specified)\r\n\r\n"
			"  Remarks:\r\n"
			"  ~ PID field may be \"self\" to target the current process, an arbitrart PID, or \"*\" to target all accessible processes.\r\n"
			"  ~ Output type field may be \"raw\" to display all queried memory info for each region, or may be \"stats\" to gather statistically common memory characteristics among the target(s)\r\n", pArgv[0]);
	}
	else {
		SelectedProcessType ProcType = SelectedProcessType::InvalidPid;
		SelectedOutputType OutputType = SelectedOutputType::InvalidOutput;
		uint32_t dwSelectedPid = 0;

		for (int32_t nX = 0; nX < nArgc; nX++) {
			if (_wcsicmp(pArgv[nX], L"--target") == 0) {
				if (_wcsicmp(pArgv[nX + 1], L"self") == 0) {
					ProcType = SelectedProcessType::SelfPid;
					dwSelectedPid = GetCurrentProcessId();
				}
				else if (_wcsicmp(pArgv[nX + 1], L"*") == 0) {
					ProcType = SelectedProcessType::AllPids;
				}
				else {
					ProcType = SelectedProcessType::SpecificPid;
					dwSelectedPid = _wtoi(pArgv[nX + 1]);
				}
			}
			else if (_wcsicmp(pArgv[nX], L"--output-type") == 0) {
				if (_wcsicmp(pArgv[nX + 1], L"raw") == 0) {
					OutputType = SelectedOutputType::Raw;
				}
				else if (_wcsicmp(pArgv[nX + 1], L"stats") == 0) {
					OutputType = SelectedOutputType::Statistics;
				}
			}
		}

		if (ProcType == SelectedProcessType::InvalidPid) {
			printf("- Invalid target process type selected\r\n");
			return 0;
		}

		if (OutputType == SelectedOutputType::InvalidOutput) {
			printf("- Invalid scan output type selected\r\n");
			return 0;
		}

		if (ProcType == SelectedProcessType::SpecificPid || ProcType == SelectedProcessType::SelfPid) {
			list<MEMORY_BASIC_INFORMATION*> ProcessMem = QueryProcessMem(dwSelectedPid);

			if (OutputType == SelectedOutputType::Raw) {
				EnumProcessMem(dwSelectedPid, (uint8_t*)-1);
			}
			else if (OutputType == SelectedOutputType::Statistics) {
				MemoryPermissionRecord* MemPermRec = new MemoryPermissionRecord(ProcessMem);
				MemPermRec->ShowRecords();
			}
		}
		else {
			PROCESSENTRY32W ProcEntry = { 0 };
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			MemoryPermissionRecord* MemPermRec = nullptr;

			if (hSnapshot != nullptr) {
				ProcEntry.dwSize = sizeof(PROCESSENTRY32W);

				if (Process32FirstW(hSnapshot, &ProcEntry)) {
					do
					{
						if (OutputType == SelectedOutputType::Raw) {
							EnumProcessMem(ProcEntry.th32ProcessID, (uint8_t*)-1);
						}
						else if (OutputType == SelectedOutputType::Statistics) {
							list<MEMORY_BASIC_INFORMATION*> ProcessMem = QueryProcessMem(ProcEntry.th32ProcessID);
							if (MemPermRec == nullptr) {
								MemPermRec = new MemoryPermissionRecord(ProcessMem);
							}
							else {
								MemPermRec->UpdateMap(ProcessMem);
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

			if (MemPermRec != nullptr) {
				MemPermRec->ShowRecords();
			}
		}
	}
}