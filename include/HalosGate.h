#include <stdio.h>
#include <windows.h>

extern VOID HellsGate(WORD wSystemCall);
extern VOID HellDescent();

EXTERN_C PVOID getntdll();

EXTERN_C DWORD halosGateUp(LPVOID Address, DWORD index);
EXTERN_C DWORD halosGateDown(LPVOID Address, DWORD index);

EXTERN_C PVOID getExportTable(
	IN PVOID moduleAddr
);

EXTERN_C PVOID getExAddressTable(
	IN PVOID moduleExportTableAddr,
	IN PVOID moduleAddr
);

EXTERN_C PVOID getExNamePointerTable(
	IN PVOID moduleExportTableAddr,
	IN PVOID moduleAddr
);

EXTERN_C PVOID getExOrdinalTable(
	IN PVOID moduleExportTableAddr,
	IN PVOID moduleAddr
);

EXTERN_C PVOID getApiAddr(
	IN DWORD apiNameStringLen,
	IN LPSTR apiNameString,
	IN PVOID moduleAddr,
	IN PVOID ExExAddressTable,
	IN PVOID ExNamePointerTable,
	IN PVOID ExOrdinalTable
);

EXTERN_C DWORD findSyscallNumber(
	IN PVOID ntdllApiAddr
);

EXTERN_C DWORD halosGate(
	IN PVOID ntdllApiAddr,
	IN WORD index
);

EXTERN_C DWORD compExplorer(
	IN PVOID explorerWString
);

