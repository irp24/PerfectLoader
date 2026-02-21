#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <wininet.h>
#pragma comment(lib, "ntdll.lib")

/*
 * Logging — set pl_log before calling inject() to redirect output.
 * Falls back to printf if NULL.
 */
typedef void (*PL_LogFunc)(const char* fmt, ...);
extern PL_LogFunc pl_log;

static inline void pl_log_default(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
}
#define PLLOG(fmt, ...) do { \
    if (pl_log) pl_log(fmt, ##__VA_ARGS__); \
    else pl_log_default(fmt, ##__VA_ARGS__); \
} while(0)

/* ---- enums ---- */
static PL_LogFunc pl_log = NULL;

typedef enum {
    PL_METHOD_MANUAL_MAP = 0,
    PL_METHOD_SET_WINDOWS_HOOK,
    PL_METHOD_SHELLCODE,
    PL_METHOD_COUNT
} PL_InjectionMethod;

static const char* PL_MethodNames[] =
{
    "Manual Map",
    "SetWindowsHookEx",
    "Shellcode"
};



typedef enum {
    PL_IAT_LOADLIBRARY = 0,
    PL_IAT_READONLY,
    PL_IAT_COUNT
} PL_IATMode;

static const char* PL_IATModeNames[] =
{
    "LoadLibrary (local resolve)",
    "ReadOnly (remote PEB walk)"
};



typedef enum {
    PL_EXEC_NT_CREATE_THREAD_EX = 0,
    PL_EXEC_QUEUE_USER_APC,
    PL_EXEC_THREAD_HIJACK,
    PL_EXEC_COUNT
} PL_ExecMethod;

static const char* PL_ExecMethodNames[] =
{
    "NtCreateThreadEx",
    "QueueUserAPC",
    "Thread Hijack",
};



typedef enum {
    PL_ALLOC_ZW_ALLOCATE = 0,
    PL_ALLOC_MAP_VIEW_OF_SECTION,
    PL_ALLOC_RWX_HUNT,
    PL_ALLOC_COUNT
} PL_AllocMethod;

static const char* PL_AllocMethodNames[] =
{
    "ZwAllocateVirtualMemory",
    "NtMapViewOfSection",
    "RWX Cave Hunt"
};



typedef enum {
    PL_OK = 0,
    PL_ERR_NO_DLL_PATH, 
    PL_ERR_ALLOC_REMOTE,
    PL_ERR_IAT_MODULE_NOT_FOUND, 
    PL_ERR_IAT_FUNC_NOT_FOUND,
    PL_ERR_THREAD_CREATE,
    PL_ERR_HOOK_PROC, 
    PL_ERR_NO_PROCESS, 
    PL_ERR_PE_INVALID,
    PL_ERR_NO_SHELLCODE,
} PL_Result;

static const char* PL_ResultStrings[] =
{
   "OK", 
   "No DLL path specified", 
   "Remote memory allocation failed",
   "IAT: module not found", 
   "IAT: function not found",
   "CreateRemoteThread failed",
   "SetWindowsHookEx: export not found", 
   "No target process handle",
   "Invalid PE file",
   "No shellcode provided",
};

/* ---- config ---- */

struct _PLRing3 {
    char                libraryPath[MAX_PATH];
    char                exportedMain[256]; // for SetWindowsHookEx
    LPCSTR              windowName;
    PL_InjectionMethod  method;
    PL_IATMode          iatMode;
    PL_ExecMethod       execMethod;
    PL_AllocMethod      allocMethod;
    HANDLE              hTargetProcess;
    BYTE*               shellcodeBytes; // caller frees
    SIZE_T              shellcodeLen;
};
extern struct _PLRing3 PLRing3;

/* ---- NT constants ---- */

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#define ViewUnmap 2

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) \
    do { (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
         (p)->RootDirectory = (r); \
         (p)->Attributes = (a); \
         (p)->ObjectName = (n); \
         (p)->SecurityDescriptor = (s); \
         (p)->SecurityQualityOfService = NULL; \
    } while(0)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#define PL_FileStandardInformation 5
#define PL_SystemProcessInformation 5

/* ---- NT types ---- */

typedef struct _PL_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} PL_CLIENT_ID;

typedef struct _PL_FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} PL_FILE_STANDARD_INFORMATION;

typedef struct _PL_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime, UserTime, CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    PL_CLIENT_ID  ClientId;
    LONG          Priority, BasePriority;
    ULONG         ContextSwitches, ThreadState, WaitReason;
} PL_SYSTEM_THREAD_INFORMATION;

typedef struct _PL_SYSTEM_PROCESS_INFORMATION {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime, UserTime, KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      UniqueProcessKey;
    SIZE_T         PeakVirtualSize, VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize, WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage, PeakPagefileUsage, PrivatePageCount;
    LARGE_INTEGER  ReadOperationCount, WriteOperationCount, OtherOperationCount;
    LARGE_INTEGER  ReadTransferCount, WriteTransferCount, OtherTransferCount;
    PL_SYSTEM_THREAD_INFORMATION Threads[1];
} PL_SYSTEM_PROCESS_INFORMATION;

// PEB structs
typedef struct _FULL_PEB_LDR_DATA
{
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} FULL_PEB_LDR_DATA;

typedef struct _LDR_ENTRY_FULL
{
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_ENTRY_FULL;

/* ---- Zw function pointers ---- */

 NTSTATUS(NTAPI* ZwClose)(HANDLE);
 NTSTATUS(NTAPI* ZwAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
 NTSTATUS(NTAPI* ZwFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
 NTSTATUS(NTAPI* ZwReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
 NTSTATUS(NTAPI* ZwWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
 NTSTATUS(NTAPI* ZwQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
 NTSTATUS(NTAPI* ZwCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
 NTSTATUS(NTAPI* ZwOpenThread)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
 NTSTATUS(NTAPI* ZwSuspendThread)(HANDLE, PULONG);
 NTSTATUS(NTAPI* ZwResumeThread)(HANDLE, PULONG);
 NTSTATUS(NTAPI* ZwGetContextThread)(HANDLE, PCONTEXT);
 NTSTATUS(NTAPI* ZwSetContextThread)(HANDLE, PCONTEXT);
 NTSTATUS(NTAPI* ZwQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
 NTSTATUS(NTAPI* ZwCreateFile)(PHANDLE, ACCESS_MASK, PVOID, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
 NTSTATUS(NTAPI* ZwReadFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
 NTSTATUS(NTAPI* ZwQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
 NTSTATUS(NTAPI* ZwCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
 NTSTATUS(NTAPI* ZwMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
 NTSTATUS(NTAPI* ZwUnmapViewOfSection)(HANDLE, PVOID);
 NTSTATUS(NTAPI* ZwQueryVirtualMemory)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
 BOOLEAN(NTAPI* RtlDosPathNameToNtPathName_U)(PCWSTR, PUNICODE_STRING, PWSTR*, PVOID);
 NTSTATUS(NTAPI* ZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

 //general utilites
static void ResolveZwApi()
 {
     static BOOL resolved = FALSE;
     if (resolved) return;

     HMODULE nt = GetModuleHandleA("ntdll.dll");

     ZwClose = GetProcAddress(nt, "ZwClose");
     ZwAllocateVirtualMemory = GetProcAddress(nt, "ZwAllocateVirtualMemory");
     ZwFreeVirtualMemory = GetProcAddress(nt, "ZwFreeVirtualMemory");
     ZwReadVirtualMemory = GetProcAddress(nt, "ZwReadVirtualMemory");
     ZwWriteVirtualMemory = GetProcAddress(nt, "ZwWriteVirtualMemory");
     ZwQueryInformationProcess = GetProcAddress(nt, "ZwQueryInformationProcess");
     ZwCreateThreadEx = GetProcAddress(nt, "ZwCreateThreadEx");
     ZwOpenThread = GetProcAddress(nt, "ZwOpenThread");
     ZwSuspendThread = GetProcAddress(nt, "ZwSuspendThread");
     ZwResumeThread = GetProcAddress(nt, "ZwResumeThread");
     ZwGetContextThread = GetProcAddress(nt, "ZwGetContextThread");
     ZwSetContextThread = GetProcAddress(nt, "ZwSetContextThread");
     ZwQueueApcThread = GetProcAddress(nt, "ZwQueueApcThread");
     ZwCreateFile = GetProcAddress(nt, "ZwCreateFile");
     ZwReadFile = GetProcAddress(nt, "ZwReadFile");
     ZwQueryInformationFile = GetProcAddress(nt, "ZwQueryInformationFile");
     ZwCreateSection = GetProcAddress(nt, "ZwCreateSection");
     ZwMapViewOfSection = GetProcAddress(nt, "ZwMapViewOfSection");
     ZwUnmapViewOfSection = GetProcAddress(nt, "ZwUnmapViewOfSection");
     ZwQueryVirtualMemory = GetProcAddress(nt, "ZwQueryVirtualMemory");
     RtlDosPathNameToNtPathName_U = GetProcAddress(nt, "RtlDosPathNameToNtPathName_U");
     ZwQuerySystemInformation = GetProcAddress(nt, "ZwQuerySystemInformation");

     resolved = TRUE;
     PLLOG("[+] Zw API resolved from ntdll\n");
 }

static PVOID ZwAllocLocal(SIZE_T size, ULONG protect)
 {
     PVOID base = NULL;
     SIZE_T sz = size;
     NTSTATUS st = ZwAllocateVirtualMemory(
         NtCurrentProcess(), &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, protect);
     return NT_SUCCESS(st) ? base : NULL;
 }

static void ZwFreeLocal(PVOID ptr)
 {
     SIZE_T sz = 0;
     ZwFreeVirtualMemory(NtCurrentProcess(), &ptr, &sz, MEM_RELEASE);
 }

static PVOID ZwAllocRemote(HANDLE hProcess, SIZE_T size, ULONG protect)
 {
     PVOID base = NULL;
     SIZE_T sz = size;
     NTSTATUS st = ZwAllocateVirtualMemory(
         hProcess, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, protect);
     return NT_SUCCESS(st) ? base : NULL;
 }

static PVOID QuerySystemProcessInfo()
 {
     ULONG bufSize = 0x80000;
     PVOID buf = ZwAllocLocal(bufSize, PAGE_READWRITE);
     while (TRUE)
     {
         ULONG retLen = 0;
         NTSTATUS st = ZwQuerySystemInformation(PL_SystemProcessInformation, buf, bufSize, &retLen);
         if (NT_SUCCESS(st))
         {
             return buf;
         }
         if (st == STATUS_INFO_LENGTH_MISMATCH)
         {
             ZwFreeLocal(buf);
             bufSize = retLen + 0x1000;
             buf = ZwAllocLocal(bufSize, PAGE_READWRITE);
         }
         else
         {
             ZwFreeLocal(buf);
             return NULL;
         }
     }
 }


 /* ---- public API ---- */

PL_Result inject(HANDLE hSection, LPVOID raw, PVOID remoteBuf, PIMAGE_NT_HEADERS nth);
