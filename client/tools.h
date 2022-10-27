#pragma once
#include "common.h"

typedef DWORD(WINAPI* PNtQueryObject)(HANDLE, DWORD, VOID*, DWORD, VOID*);
typedef DWORD(WINAPI* PNtQuerySystemInformation)(DWORD, VOID*, DWORD, ULONG*);
typedef DWORD(WINAPI* PNtQueryInformationThread)(HANDLE, ULONG, PVOID, DWORD, DWORD*);
typedef DWORD(WINAPI* PNtQueryInformationFile)(HANDLE, PVOID, PVOID, DWORD, DWORD);
typedef DWORD(WINAPI* PNtQueryInformationProcess)(HANDLE, DWORD, PVOID, DWORD, PVOID);

static PNtQuerySystemInformation	NtQuerySystemInformation;
static PNtQueryObject				NtQueryObject;
static PNtQueryInformationThread	NtQueryInformationThread;
static PNtQueryInformationFile		NtQueryInformationFile;
static PNtQueryInformationProcess	NtQueryInformationProcess;

typedef struct _UNICODE_STRING {
	WORD  Length;
	WORD  MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING;

typedef struct _PROCESS_BASIC_INFORMATION {
	DWORD ExitStatus;
	PVOID PebBaseAddress;
	DWORD AffinityMask;
	DWORD BasePriority;
	DWORD UniqueProcessId;
	DWORD InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _VM_COUNTERS {
	DWORD PeakVirtualSize;
	DWORD VirtualSize;
	DWORD PageFaultCount;
	DWORD PeakWorkingSetSize;
	DWORD WorkingSetSize;
	DWORD QuotaPeakPagedPoolUsage;
	DWORD QuotaPagedPoolUsage;
	DWORD QuotaPeakNonPagedPoolUsage;
	DWORD QuotaNonPagedPoolUsage;
	DWORD PagefileUsage;
	DWORD PeakPagefileUsage;
} VM_COUNTERS;

typedef struct _SYSTEM_THREAD {
	DWORD        u1;
	DWORD        u2;
	DWORD        u3;
	DWORD        u4;
	DWORD        ProcessId;
	DWORD        ThreadId;
	DWORD        dPriority;
	DWORD        dBasePriority;
	DWORD        dContextSwitches;
	DWORD        dThreadState;      // 2=running, 5=waiting
	DWORD        WaitReason;
	DWORD        u5;
	DWORD        u6;
	DWORD        u7;
	DWORD        u8;
	DWORD        u9;
} SYSTEM_THREAD;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	DWORD          dNext;
	DWORD          dThreadCount;
	DWORD          dReserved01;
	DWORD          dReserved02;
	DWORD          dReserved03;
	DWORD          dReserved04;
	DWORD          dReserved05;
	DWORD          dReserved06;
	LARGE_INTEGER  qCreateTime;
	LARGE_INTEGER  qUserTime;
	LARGE_INTEGER  qKernelTime;
	UNICODE_STRING usName;
	DWORD	       BasePriority;
	DWORD          dUniqueProcessId;
	DWORD          dInheritedFromUniqueProcessId;
	DWORD          dHandleCount;
	DWORD          dReserved07;
	DWORD          dReserved08;
	VM_COUNTERS    VmCounters;
	DWORD          dCommitCharge;
	SYSTEM_THREAD  Threads[1];
} SYSTEM_PROCESS_INFORMATION;

/*enum {
	OB_TYPE_UNKNOWN = 0,
	OB_TYPE_TYPE = 1,
	OB_TYPE_DIRECTORY,
	OB_TYPE_SYMBOLIC_LINK,
	OB_TYPE_TOKEN,
	OB_TYPE_PROCESS,
	OB_TYPE_THREAD,
	OB_TYPE_UNKNOWN_7,
	OB_TYPE_EVENT,
	OB_TYPE_EVENT_PAIR,
	OB_TYPE_MUTANT,
	OB_TYPE_UNKNOWN_11,
	OB_TYPE_SEMAPHORE,
	OB_TYPE_TIMER,
	OB_TYPE_PROFILE,
	OB_TYPE_WINDOW_STATION,
	OB_TYPE_DESKTOP,
	OB_TYPE_SECTION,
	OB_TYPE_KEY,
	OB_TYPE_PORT,
	OB_TYPE_WAITABLE_PORT,
	OB_TYPE_UNKNOWN_21,
	OB_TYPE_UNKNOWN_22,
	OB_TYPE_UNKNOWN_23,
	OB_TYPE_UNKNOWN_24,
	//OB_TYPE_CONTROLLER,
	//OB_TYPE_DEVICE,
	//OB_TYPE_DRIVER,
	OB_TYPE_IO_COMPLETION,
	OB_TYPE_FILE
} SystemHandleType;
*/
typedef struct _SYSTEM_HANDLE {
	DWORD	ProcessID;
	WORD	HandleType;
	WORD	HandleNumber;
	DWORD	KernelAddress;
	DWORD	Flags;
} SYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	DWORD			Count;
	SYSTEM_HANDLE	Handles[1];
} SYSTEM_HANDLE_INFORMATION;

typedef struct _GetFileNameThreadParam {
	HANDLE		hFile;
	char* pName;
	ULONG		rc;
} GetFileNameThreadParam;

typedef struct _FileLinkedList {
	char file_path[MAX_PATH];
	int priority;
	long long size;
	_FileLinkedList* next;
	_FileLinkedList* pre;
}FileLinkedList, * pFileLinkedList;

#define AlignSectionHeader(Alignment,Size,Address) ((Size % Alignment)==0) ? Address + Size : (Address + (Size / Alignment + 1) * Alignment)

PVOID MyGetProcAddress(HINSTANCE ModuleBase, LPSTR FuncName);

void close_handles(pFileLinkedList file_head);
bool LoadAPI();
void list_files(pFileLinkedList&, pFileLinkedList&);
bool get_list(char dir[MAX_PATH], pFileLinkedList& file_head, pFileLinkedList& file_tail);
bool load_public_key(LPVOID pub_key,DWORD*);