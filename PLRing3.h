#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <wininet.h>
#pragma comment(lib, "ntdll.lib")

// ---------------------------------------------------------------
//  Logging — redirectable to GUI or console
// ---------------------------------------------------------------
typedef void (*PL_LogFunc)(const char* fmt, ...);
static PL_LogFunc pl_log = NULL;

// fallback to printf if no callback set
static void pl_log_default(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

#define PLLOG(fmt, ...) do { \
    if (pl_log) pl_log(fmt, ##__VA_ARGS__); \
    else pl_log_default(fmt, ##__VA_ARGS__); \
} while(0)

// ---------------------------------------------------------------
//  Enums — cleaner than separate BOOLs
// ---------------------------------------------------------------
typedef enum {
    PL_METHOD_MANUAL_MAP = 0,
    PL_METHOD_SET_WINDOWS_HOOK,
    PL_METHOD_SHELLCODE,
    PL_METHOD_COUNT
} PL_InjectionMethod;

static const char* PL_MethodNames[] = {
    "Manual Map",
    "SetWindowsHookEx",
    "Shellcode"
};

typedef enum {
    PL_IAT_LOADLIBRARY = 0,   // load modules locally, resolve with GetProcAddress
    PL_IAT_READONLY,           // walk remote PEB, never load anything locally
    PL_IAT_COUNT
} PL_IATMode;

static const char* PL_IATModeNames[] = {
    "LoadLibrary (local resolve)",
    "ReadOnly (remote PEB walk)"
};

typedef enum {
    PL_EXEC_NT_CREATE_THREAD_EX = 0,
    PL_EXEC_QUEUE_USER_APC,
    PL_EXEC_THREAD_HIJACK,
    PL_EXEC_COUNT
} PL_ExecMethod;

static const char* PL_ExecMethodNames[] = {
    "NtCreateThreadEx",
    "QueueUserAPC",
    "Thread Hijack"
};

typedef enum {
    PL_ALLOC_ZW_ALLOCATE = 0,
    PL_ALLOC_MAP_VIEW_OF_SECTION,
    PL_ALLOC_RWX_HUNT,
    PL_ALLOC_COUNT
} PL_AllocMethod;

static const char* PL_AllocMethodNames[] = {
    "ZwAllocateVirtualMemory",
    "NtMapViewOfSection",
    "RWX Cave Hunt"
};

typedef enum {
    PL_OK = 0,
    PL_ERR_NO_DLL_PATH,
    PL_ERR_FILE_OPEN,
    PL_ERR_FILE_READ,
    PL_ERR_PE_INVALID,
    PL_ERR_ALLOC_LOCAL,
    PL_ERR_ALLOC_REMOTE,
    PL_ERR_RELOC_FAILED,
    PL_ERR_IAT_MODULE_NOT_FOUND,
    PL_ERR_IAT_FUNC_NOT_FOUND,
    PL_ERR_WRITE_REMOTE,
    PL_ERR_THREAD_CREATE,
    PL_ERR_HOOK_LOAD,
    PL_ERR_HOOK_PROC,
    PL_ERR_HOOK_INSTALL,
    PL_ERR_NO_PROCESS,
    PL_ERR_NO_SHELLCODE,
} PL_Result;

static const char* PL_ResultStrings[] = {
    "OK",
    "No DLL path specified",
    "Failed to open DLL file",
    "Failed to read DLL file",
    "Invalid PE file",
    "Local memory allocation failed",
    "Remote memory allocation failed",
    "Relocation fixup failed",
    "IAT: module not found",
    "IAT: function not found",
    "WriteProcessMemory failed",
    "CreateRemoteThread failed",
    "SetWindowsHookEx: LoadLibrary failed",
    "SetWindowsHookEx: export not found",
    "SetWindowsHookEx: hook install failed",
    "No target process handle",
    "No shellcode provided",
};

// ---------------------------------------------------------------
//  Config struct
// ---------------------------------------------------------------
struct _PLRing3 {
    char                libraryPath[MAX_PATH];  // fixed buffer, safe to edit from GUI
    char                exportedMain[256];       // for SetWindowsHookEx
    LPCSTR              windowName;       // title of the target process's main window

    PL_InjectionMethod  method;
    PL_IATMode          iatMode;

    BOOL                fixIAT;
    BOOL                fixRelocations;

    PL_ExecMethod       execMethod;
    PL_AllocMethod      allocMethod;

    HANDLE              hTargetProcess;
    BYTE*               shellcodeBytes;  // heap-allocated, caller must free
    SIZE_T              shellcodeLen;
} PLRing3;

// ---------------------------------------------------------------
//  Zw* syscall wrappers — resolved from ntdll at runtime
// ---------------------------------------------------------------

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

typedef struct _PL_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} PL_CLIENT_ID;

typedef struct _PL_FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} PL_FILE_STANDARD_INFORMATION;

#define PL_FileStandardInformation 5
#define PL_SystemProcessInformation 5

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef struct _PL_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    PL_CLIENT_ID  ClientId;
    LONG          Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    ULONG         WaitReason;
} PL_SYSTEM_THREAD_INFORMATION;

typedef struct _PL_SYSTEM_PROCESS_INFORMATION {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      UniqueProcessKey;
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         PrivatePageCount;
    LARGE_INTEGER  ReadOperationCount;
    LARGE_INTEGER  WriteOperationCount;
    LARGE_INTEGER  OtherOperationCount;
    LARGE_INTEGER  ReadTransferCount;
    LARGE_INTEGER  WriteTransferCount;
    LARGE_INTEGER  OtherTransferCount;
    PL_SYSTEM_THREAD_INFORMATION Threads[1];
} PL_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(NTAPI* pfnZwClose)(HANDLE);
typedef NTSTATUS(NTAPI* pfnZwAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pfnZwFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS(NTAPI* pfnZwReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* pfnZwWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* pfnZwQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pfnZwCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* pfnZwOpenThread)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
typedef NTSTATUS(NTAPI* pfnZwSuspendThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* pfnZwResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* pfnZwGetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* pfnZwSetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* pfnZwQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS(NTAPI* pfnZwCreateFile)(PHANDLE, ACCESS_MASK, PVOID, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pfnZwReadFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(NTAPI* pfnZwQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pfnZwCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* pfnZwMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pfnZwUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pfnZwQueryVirtualMemory)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
typedef BOOLEAN(NTAPI* pfnRtlDosPathNameToNtPathName_U)(PCWSTR, PUNICODE_STRING, PWSTR*, PVOID);
typedef VOID(NTAPI* pfnRtlFreeUnicodeString)(PUNICODE_STRING);
typedef NTSTATUS(NTAPI* pfnZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

static struct {
    BOOL resolved;
    pfnZwClose                      ZwClose;
    pfnZwAllocateVirtualMemory      ZwAllocateVirtualMemory;
    pfnZwFreeVirtualMemory          ZwFreeVirtualMemory;
    pfnZwReadVirtualMemory          ZwReadVirtualMemory;
    pfnZwWriteVirtualMemory         ZwWriteVirtualMemory;
    pfnZwQueryInformationProcess    ZwQueryInformationProcess;
    pfnZwCreateThreadEx             ZwCreateThreadEx;
    pfnZwOpenThread                 ZwOpenThread;
    pfnZwSuspendThread              ZwSuspendThread;
    pfnZwResumeThread               ZwResumeThread;
    pfnZwGetContextThread           ZwGetContextThread;
    pfnZwSetContextThread           ZwSetContextThread;
    pfnZwQueueApcThread             ZwQueueApcThread;
    pfnZwCreateFile                 ZwCreateFile;
    pfnZwReadFile                   ZwReadFile;
    pfnZwQueryInformationFile       ZwQueryInformationFile;
    pfnZwCreateSection              ZwCreateSection;
    pfnZwMapViewOfSection           ZwMapViewOfSection;
    pfnZwUnmapViewOfSection         ZwUnmapViewOfSection;
    pfnZwQueryVirtualMemory         ZwQueryVirtualMemory;
    pfnRtlDosPathNameToNtPathName_U RtlDosPathNameToNtPathName_U;
    pfnRtlFreeUnicodeString         RtlFreeUnicodeString;
    pfnZwQuerySystemInformation     ZwQuerySystemInformation;
} ZwApi = { 0 };

static void _ResolveZwApi(void) {
    if (ZwApi.resolved) return;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
#define _ZW_RESOLVE(name) ZwApi.name = (pfn##name)GetProcAddress(ntdll, #name)
    _ZW_RESOLVE(ZwClose);
    _ZW_RESOLVE(ZwAllocateVirtualMemory);
    _ZW_RESOLVE(ZwFreeVirtualMemory);
    _ZW_RESOLVE(ZwReadVirtualMemory);
    _ZW_RESOLVE(ZwWriteVirtualMemory);
    _ZW_RESOLVE(ZwQueryInformationProcess);
    _ZW_RESOLVE(ZwCreateThreadEx);
    _ZW_RESOLVE(ZwOpenThread);
    _ZW_RESOLVE(ZwSuspendThread);
    _ZW_RESOLVE(ZwResumeThread);
    _ZW_RESOLVE(ZwGetContextThread);
    _ZW_RESOLVE(ZwSetContextThread);
    _ZW_RESOLVE(ZwQueueApcThread);
    _ZW_RESOLVE(ZwCreateFile);
    _ZW_RESOLVE(ZwReadFile);
    _ZW_RESOLVE(ZwQueryInformationFile);
    _ZW_RESOLVE(ZwCreateSection);
    _ZW_RESOLVE(ZwMapViewOfSection);
    _ZW_RESOLVE(ZwUnmapViewOfSection);
    _ZW_RESOLVE(ZwQueryVirtualMemory);
    _ZW_RESOLVE(RtlDosPathNameToNtPathName_U);
    _ZW_RESOLVE(RtlFreeUnicodeString);
    _ZW_RESOLVE(ZwQuerySystemInformation);
#undef _ZW_RESOLVE
    ZwApi.resolved = TRUE;
}

static __forceinline void _ZwFreeLocal(PVOID ptr) {
    SIZE_T sz = 0;
    ZwApi.ZwFreeVirtualMemory(NtCurrentProcess(), &ptr, &sz, MEM_RELEASE);
}

static __forceinline PVOID _ZwAllocLocal(SIZE_T size, ULONG protect) {
    PVOID base = NULL;
    SIZE_T sz = size;
    NTSTATUS st = ZwApi.ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, protect);
    return NT_SUCCESS(st) ? base : NULL;
}

static __forceinline PVOID _ZwAllocRemote(HANDLE hProcess, SIZE_T size, ULONG protect) {
    PVOID base = NULL;
    SIZE_T sz = size;
    NTSTATUS st = ZwApi.ZwAllocateVirtualMemory(hProcess, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, protect);
    return NT_SUCCESS(st) ? base : NULL;
}

// Returns an NT-allocated buffer with the full SYSTEM_PROCESS_INFORMATION chain.
// Caller must _ZwFreeLocal() the returned pointer. Returns NULL on failure.
static PBYTE _QuerySystemProcessInfo(void) {
    ULONG bufSize = 0x80000;
    PBYTE buf = (PBYTE)_ZwAllocLocal(bufSize, PAGE_READWRITE);
    if (!buf) return NULL;
    for (;;) {
        ULONG retLen = 0;
        NTSTATUS st = ZwApi.ZwQuerySystemInformation(PL_SystemProcessInformation,
            buf, bufSize, &retLen);
        if (NT_SUCCESS(st)) return buf;
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            _ZwFreeLocal(buf);
            bufSize = retLen + 0x1000;
            buf = (PBYTE)_ZwAllocLocal(bufSize, PAGE_READWRITE);
            if (!buf) return NULL;
        } else {
            _ZwFreeLocal(buf);
            return NULL;
        }
    }
}

// ---------------------------------------------------------------
//  RWX cave hunter
// ---------------------------------------------------------------
static PVOID _HuntRWXCave(HANDLE hProcess, SIZE_T requiredSize) {
    MEMORY_BASIC_INFORMATION mbi;
    PVOID addr = NULL;

    while (NT_SUCCESS(ZwApi.ZwQueryVirtualMemory(hProcess, addr, 0 /*MemoryBasicInformation*/,
        &mbi, sizeof(mbi), NULL)))
    {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_EXECUTE_READWRITE) &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.RegionSize >= requiredSize)
        {
            PBYTE localCopy = (PBYTE)_ZwAllocLocal(mbi.RegionSize, PAGE_READWRITE);
            if (localCopy) {
                SIZE_T bytesRead = 0;
                if (NT_SUCCESS(ZwApi.ZwReadVirtualMemory(hProcess, mbi.BaseAddress,
                    localCopy, mbi.RegionSize, &bytesRead)))
                {
                    SIZE_T runLen = 0;
                    SIZE_T runStart = 0;
                    for (SIZE_T i = 0; i < bytesRead; i++) {
                        if (localCopy[i] == 0x00) {
                            if (runLen == 0) runStart = i;
                            runLen++;
                            if (runLen >= requiredSize) {
                                PVOID result = (PVOID)((uintptr_t)mbi.BaseAddress + runStart);
                                _ZwFreeLocal(localCopy);
                                return result;
                            }
                        } else {
                            runLen = 0;
                        }
                    }
                }
                _ZwFreeLocal(localCopy);
            }
        }

        addr = (PVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        if ((uintptr_t)addr <= (uintptr_t)mbi.BaseAddress)
            break;
    }

    return NULL;
}

// ---------------------------------------------------------------
//  PEB structures for remote module enumeration
// ---------------------------------------------------------------
typedef struct _FULL_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} FULL_PEB_LDR_DATA;

typedef struct _LDR_ENTRY_FULL {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_ENTRY_FULL;

// ---------------------------------------------------------------
//  Remote PEB walk — find a module base in a remote process
// ---------------------------------------------------------------
PVOID RemoteGetModuleBaseFromPEB(HANDLE hProcess, const char* moduleName) {
    _ResolveZwApi();
    WCHAR wName[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, moduleName, -1, wName, MAX_PATH);

    PROCESS_BASIC_INFORMATION pbi;
    if (!NT_SUCCESS(ZwApi.ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL))) {
        PLLOG("[-] ZwQueryInformationProcess failed\n");
        return NULL;
    }

    PEB peb;
    if (!NT_SUCCESS(ZwApi.ZwReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL))) {
        PLLOG("[-] Failed to read remote PEB\n");
        return NULL;
    }

    FULL_PEB_LDR_DATA ldr;
    if (!NT_SUCCESS(ZwApi.ZwReadVirtualMemory(hProcess, peb.Ldr, &ldr, sizeof(ldr), NULL))) {
        PLLOG("[-] Failed to read remote Ldr\n");
        return NULL;
    }

    PVOID headRemote = (PVOID)((PBYTE)peb.Ldr + offsetof(FULL_PEB_LDR_DATA, InLoadOrderModuleList));
    PVOID entryRemote = ldr.InLoadOrderModuleList.Flink;

    while (entryRemote != headRemote) {
        LDR_ENTRY_FULL entry;
        memset(&entry, 0, sizeof(entry));
        if (!NT_SUCCESS(ZwApi.ZwReadVirtualMemory(hProcess, entryRemote, &entry, sizeof(entry), NULL)))
            break;

        if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0) {
            WCHAR nameBuf[MAX_PATH];
            memset(nameBuf, 0, sizeof(nameBuf));
            SIZE_T readLen = entry.BaseDllName.Length;
            if (readLen > (MAX_PATH - 1) * 2)
                readLen = (MAX_PATH - 1) * 2;
            if (NT_SUCCESS(ZwApi.ZwReadVirtualMemory(hProcess, entry.BaseDllName.Buffer, nameBuf, readLen, NULL))) {
                if (_wcsicmp(nameBuf, wName) == 0)
                    return entry.DllBase;
            }
        }
        entryRemote = entry.InLoadOrderLinks.Flink;
    }
    return NULL;
}

// ---------------------------------------------------------------
//  Remote GetProcAddress — read exports from a remote process
// ---------------------------------------------------------------
FARPROC RemoteCustomGetProcAddress(HANDLE hProcess, PVOID remoteBase, LPCSTR procName) {
    _ResolveZwApi();
    IMAGE_DOS_HEADER dos;
    if (!NT_SUCCESS(ZwApi.ZwReadVirtualMemory(hProcess, remoteBase, &dos, sizeof(dos), NULL)))
        return NULL;

    IMAGE_NT_HEADERS nt;
    if (!NT_SUCCESS(ZwApi.ZwReadVirtualMemory(hProcess, (PBYTE)remoteBase + dos.e_lfanew, &nt, sizeof(nt), NULL)))
        return NULL;

    IMAGE_DATA_DIRECTORY expDataDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDataDir.VirtualAddress)
        return NULL;

    IMAGE_EXPORT_DIRECTORY expDir;
    if (!NT_SUCCESS(ZwApi.ZwReadVirtualMemory(hProcess, (PBYTE)remoteBase + expDataDir.VirtualAddress, &expDir, sizeof(expDir), NULL)))
        return NULL;

    uintptr_t funcIdx = (uintptr_t)-1;

    if ((ULONG_PTR)procName >> 16 == 0) {
        funcIdx = (uintptr_t)(ULONG_PTR)procName - expDir.Base;
        if (funcIdx >= expDir.NumberOfFunctions)
            return NULL;
    }
    else {
        for (DWORD i = 0; i < expDir.NumberOfNames; i++) {
            DWORD nameRVA = 0;
            ZwApi.ZwReadVirtualMemory(hProcess, (PBYTE)remoteBase + expDir.AddressOfNames + i * sizeof(DWORD), &nameRVA, sizeof(DWORD), NULL);
            char exportedName[256];
            memset(exportedName, 0, sizeof(exportedName));
            ZwApi.ZwReadVirtualMemory(hProcess, (PBYTE)remoteBase + nameRVA, exportedName, sizeof(exportedName) - 1, NULL);
            if (strcmp(exportedName, procName) == 0) {
                WORD nameOrd = 0;
                ZwApi.ZwReadVirtualMemory(hProcess, (PBYTE)remoteBase + expDir.AddressOfNameOrdinals + i * sizeof(WORD), &nameOrd, sizeof(WORD), NULL);
                funcIdx = nameOrd;
                break;
            }
        }
        if (funcIdx == (uintptr_t)-1)
            return NULL;
    }

    DWORD funcRVA = 0;
    ZwApi.ZwReadVirtualMemory(hProcess, (PBYTE)remoteBase + expDir.AddressOfFunctions + funcIdx * sizeof(DWORD), &funcRVA, sizeof(DWORD), NULL);
    if (!funcRVA)
        return NULL;

    // forwarded export handling
    if (funcRVA >= expDataDir.VirtualAddress && funcRVA < expDataDir.VirtualAddress + expDataDir.Size) {
        char fwdSrc[256];
        memset(fwdSrc, 0, sizeof(fwdSrc));
        ZwApi.ZwReadVirtualMemory(hProcess, (PBYTE)remoteBase + funcRVA, fwdSrc, sizeof(fwdSrc) - 1, NULL);

        char* dot = fwdSrc;
        while (*dot && *dot != '.') dot++;
        if (!*dot) return NULL;
        *dot = '\0';
        char* fwdFunc = dot + 1;

        char dllName[264];
        int k;
        for (k = 0; fwdSrc[k]; k++) dllName[k] = fwdSrc[k];
        int hasDot = 0;
        for (int m = 0; m < k; m++) { if (fwdSrc[m] == '.') { hasDot = 1; break; } }
        if (!hasDot) { dllName[k++] = '.'; dllName[k++] = 'd'; dllName[k++] = 'l'; dllName[k++] = 'l'; }
        dllName[k] = '\0';

        PVOID fwdMod = RemoteGetModuleBaseFromPEB(hProcess, dllName);
        if (!fwdMod) return NULL;

        if (fwdFunc[0] == '#') {
            ULONG ord = 0;
            for (char* p = fwdFunc + 1; *p >= '0' && *p <= '9'; p++)
                ord = ord * 10 + (*p - '0');
            return RemoteCustomGetProcAddress(hProcess, fwdMod, (LPCSTR)(ULONG_PTR)ord);
        }
        return RemoteCustomGetProcAddress(hProcess, fwdMod, fwdFunc);
    }

    return (FARPROC)((PBYTE)remoteBase + funcRVA);
}

// ---------------------------------------------------------------
//  Shared remote execution dispatcher
// ---------------------------------------------------------------
static PL_Result _ExecuteRemote(LPVOID ep)
{
    switch (PLRing3.execMethod)
    {
    case PL_EXEC_NT_CREATE_THREAD_EX:
    {
        PLLOG("[*] ZwCreateThreadEx at %p\n", ep);
        HANDLE hThread = NULL;
        NTSTATUS st = ZwApi.ZwCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
            PLRing3.hTargetProcess, ep, NULL, 0, 0, 0x1000, 0x100000, NULL);
        if (!NT_SUCCESS(st) || !hThread) {
            PLLOG("[-] ZwCreateThreadEx failed: 0x%08lX\n", (unsigned long)st);
            return PL_ERR_THREAD_CREATE;
        }
        PLLOG("[+] Thread created via ZwCreateThreadEx (handle=%p)\n", hThread);
        ZwApi.ZwClose(hThread);
        return PL_OK;
    }
    case PL_EXEC_QUEUE_USER_APC:
    {
        PLLOG("[*] ZwQueueApcThread at %p\n", ep);
        DWORD pid = GetProcessId(PLRing3.hTargetProcess);
        PBYTE buf = _QuerySystemProcessInfo();
        if (!buf) {
            PLLOG("[-] ZwQuerySystemInformation failed\n");
            return PL_ERR_THREAD_CREATE;
        }
        int queued = 0;
        PL_SYSTEM_PROCESS_INFORMATION* proc = (PL_SYSTEM_PROCESS_INFORMATION*)buf;
        for (;;) {
            if ((DWORD)(ULONG_PTR)proc->UniqueProcessId == pid) {
                for (ULONG i = 0; i < proc->NumberOfThreads; i++) {
                    HANDLE ht = NULL;
                    OBJECT_ATTRIBUTES oa;
                    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
                    PL_CLIENT_ID cid;
                    cid.UniqueProcess = NULL;
                    cid.UniqueThread = proc->Threads[i].ClientId.UniqueThread;
                    if (NT_SUCCESS(ZwApi.ZwOpenThread(&ht, THREAD_SET_CONTEXT, &oa, &cid)) && ht) {
                        ZwApi.ZwQueueApcThread(ht, ep, NULL, NULL, NULL);
                        ZwApi.ZwClose(ht);
                        queued++;
                    }
                }
                break;
            }
            if (!proc->NextEntryOffset) break;
            proc = (PL_SYSTEM_PROCESS_INFORMATION*)((PBYTE)proc + proc->NextEntryOffset);
        }
        _ZwFreeLocal(buf);
        if (!queued) {
            PLLOG("[-] No threads found for ZwQueueApcThread\n");
            return PL_ERR_THREAD_CREATE;
        }
        PLLOG("[+] APC queued to %d thread(s)\n", queued);
        return PL_OK;
    }
    case PL_EXEC_THREAD_HIJACK:
    {
        PLLOG("[*] Thread hijack at %p\n", ep);
        DWORD pid = GetProcessId(PLRing3.hTargetProcess);
        PBYTE buf = _QuerySystemProcessInfo();
        if (!buf) {
            PLLOG("[-] ZwQuerySystemInformation failed\n");
            return PL_ERR_THREAD_CREATE;
        }
        HANDLE hThread = NULL;
        PL_SYSTEM_PROCESS_INFORMATION* proc = (PL_SYSTEM_PROCESS_INFORMATION*)buf;
        for (;;) {
            if ((DWORD)(ULONG_PTR)proc->UniqueProcessId == pid) {
                for (ULONG i = 0; i < proc->NumberOfThreads && !hThread; i++) {
                    OBJECT_ATTRIBUTES oa;
                    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
                    PL_CLIENT_ID cid;
                    cid.UniqueProcess = NULL;
                    cid.UniqueThread = proc->Threads[i].ClientId.UniqueThread;
                    HANDLE ht = NULL;
                    if (NT_SUCCESS(ZwApi.ZwOpenThread(&ht,
                        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                        &oa, &cid)) && ht)
                        hThread = ht;
                }
                break;
            }
            if (!proc->NextEntryOffset) break;
            proc = (PL_SYSTEM_PROCESS_INFORMATION*)((PBYTE)proc + proc->NextEntryOffset);
        }
        _ZwFreeLocal(buf);
        if (!hThread) {
            PLLOG("[-] No thread found for hijack\n");
            return PL_ERR_THREAD_CREATE;
        }
        if (!NT_SUCCESS(ZwApi.ZwSuspendThread(hThread, NULL))) {
            PLLOG("[-] ZwSuspendThread failed\n");
            ZwApi.ZwClose(hThread); return PL_ERR_THREAD_CREATE;
        }
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (!NT_SUCCESS(ZwApi.ZwGetContextThread(hThread, &ctx))) {
            PLLOG("[-] ZwGetContextThread failed\n");
            ZwApi.ZwResumeThread(hThread, NULL); ZwApi.ZwClose(hThread); return PL_ERR_THREAD_CREATE;
        }
#ifdef _WIN64
        ctx.Rip = (DWORD64)ep;
#else
        ctx.Eip = (DWORD)(uintptr_t)ep;
#endif
        if (!NT_SUCCESS(ZwApi.ZwSetContextThread(hThread, &ctx))) {
            PLLOG("[-] ZwSetContextThread failed\n");
            ZwApi.ZwResumeThread(hThread, NULL); ZwApi.ZwClose(hThread); return PL_ERR_THREAD_CREATE;
        }
        ZwApi.ZwResumeThread(hThread, NULL);
        ZwApi.ZwClose(hThread);
        PLLOG("[+] Thread hijacked, IP redirected to %p\n", ep);
        return PL_OK;
    }
    default:
        return PL_ERR_THREAD_CREATE;
    }
}

// ---------------------------------------------------------------
//  SetWindowsHookEx injection
// ---------------------------------------------------------------
static PL_Result _SetWindowsHookEx_inject(void)//https://cocomelonc.github.io/tutorial/2021/11/25/malware-injection-7.html
{
    WCHAR wpath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, PLRing3.libraryPath, -1, wpath, MAX_PATH);

    HMODULE lib = LoadLibraryW(wpath);
    if (!lib) {
        PLLOG("[!] LoadLibrary failed: %lu\n", GetLastError());
        return PL_ERR_HOOK_LOAD;
    }

    if (PLRing3.exportedMain[0] == '\0') {
        PLLOG("[!] No export name specified for SetWindowsHookEx\n");
        FreeLibrary(lib);
        return PL_ERR_HOOK_PROC;
    }

    HOOKPROC proc = (HOOKPROC)GetProcAddress(lib, PLRing3.exportedMain);
    if (!proc) {
        PLLOG("[!] Export '%s' not found in DLL\n", PLRing3.exportedMain);
        FreeLibrary(lib);
        return PL_ERR_HOOK_PROC;
    }

    HWND hWnd = FindWindowA(NULL, PLRing3.windowName);

    DWORD pid = 0;
    DWORD tid = GetWindowThreadProcessId(hWnd, &pid);

    HHOOK hook = SetWindowsHookExW(WH_GETMESSAGE, proc, lib, tid);
    if (!hook) {
        PLLOG("[!] SetWindowsHookEx failed: %lu\n", GetLastError());
        FreeLibrary(lib);
        return PL_ERR_HOOK_INSTALL;
    }

    PLLOG("[+] Hook installed, triggering...\n");
    for (int i = 0; i < 8; i++) {
        Sleep(500);
        PostThreadMessage(tid, WM_USER + 432, 0, (LPARAM)hook);
    }
    return PL_OK;
}

// ---------------------------------------------------------------
//  Manual Map injection
// ---------------------------------------------------------------
static PL_Result _ManualMap_inject(void)
{
    _ResolveZwApi();

    if (!PLRing3.hTargetProcess) {
        PLLOG("[-] No target process handle\n");
        return PL_ERR_NO_PROCESS;
    }

    HANDLE hSection = NULL;

    // open the DLL file via ZwCreateFile
    WCHAR wFilePath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, PLRing3.libraryPath, -1, wFilePath, MAX_PATH);
    UNICODE_STRING ntPath = { 0 };
    if (!ZwApi.RtlDosPathNameToNtPathName_U(wFilePath, &ntPath, NULL, NULL)) {
        PLLOG("[-] RtlDosPathNameToNtPathName_U failed\n");
        return PL_ERR_FILE_OPEN;
    }
    OBJECT_ATTRIBUTES fileOa;
    InitializeObjectAttributes(&fileOa, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS st = ZwApi.ZwCreateFile(&hFile, FILE_GENERIC_READ, &fileOa, &iosb,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ZwApi.RtlFreeUnicodeString(&ntPath);
    if (!NT_SUCCESS(st)) {
        PLLOG("[-] ZwCreateFile failed: 0x%08lX\n", (unsigned long)st);
        return PL_ERR_FILE_OPEN;
    }
    PLLOG("[+] Opened: %s\n", PLRing3.libraryPath);

    // get file size via ZwQueryInformationFile
    PL_FILE_STANDARD_INFORMATION fsi;
    IO_STATUS_BLOCK iosbSize;
    st = ZwApi.ZwQueryInformationFile(hFile, &iosbSize, &fsi, sizeof(fsi), PL_FileStandardInformation);
    if (!NT_SUCCESS(st)) {
        ZwApi.ZwClose(hFile);
        return PL_ERR_FILE_READ;
    }
    DWORD fileSize = (DWORD)fsi.EndOfFile.LowPart;
    PLLOG("[+] File size: %lu bytes\n", fileSize);

    LPVOID rawBuf = _ZwAllocLocal((SIZE_T)fileSize, PAGE_READWRITE);
    if (!rawBuf) { ZwApi.ZwClose(hFile); return PL_ERR_ALLOC_LOCAL; }

    IO_STATUS_BLOCK iosbRead;
    LARGE_INTEGER readOffset = { 0 };
    st = ZwApi.ZwReadFile(hFile, NULL, NULL, NULL, &iosbRead, rawBuf, fileSize, &readOffset, NULL);
    ZwApi.ZwClose(hFile);
    if (!NT_SUCCESS(st)) {
        _ZwFreeLocal(rawBuf);
        return PL_ERR_FILE_READ;
    }
    DWORD bytesRead = (DWORD)iosbRead.Information;
    PLLOG("[+] Read %lu bytes\n", bytesRead);

    // parse PE
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)rawBuf;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        PLLOG("[-] Not a valid PE (bad DOS signature)\n");
        _ZwFreeLocal(rawBuf);
        return PL_ERR_PE_INVALID;
    }

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((uintptr_t)rawBuf + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        PLLOG("[-] Not a valid PE (bad NT signature)\n");
        _ZwFreeLocal(rawBuf);
        return PL_ERR_PE_INVALID;
    }

    PLLOG("[+] ImageBase=0x%IX  EP=0x%08X  Sections=%u  SizeOfImage=0x%X\n",
        (uintptr_t)ntHeader->OptionalHeader.ImageBase,
        ntHeader->OptionalHeader.AddressOfEntryPoint,
        ntHeader->FileHeader.NumberOfSections,
        ntHeader->OptionalHeader.SizeOfImage);

    // map sections locally
    LPVOID mappedBuf = _ZwAllocLocal((SIZE_T)ntHeader->OptionalHeader.SizeOfImage, PAGE_READWRITE);
    if (!mappedBuf) {
        _ZwFreeLocal(rawBuf);
        return PL_ERR_ALLOC_LOCAL;
    }

    memcpy(mappedBuf, rawBuf, ntHeader->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntHeader);
    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (sec->SizeOfRawData > 0) {
            memcpy((PVOID)((uintptr_t)mappedBuf + sec->VirtualAddress),
                (PVOID)((uintptr_t)rawBuf + sec->PointerToRawData),
                sec->SizeOfRawData);
            PLLOG("[+] Section [%.*s]  VA=0x%08X  size=0x%X\n",
                IMAGE_SIZEOF_SHORT_NAME, (char*)sec->Name,
                sec->VirtualAddress, sec->SizeOfRawData);
        }
        sec++;
    }

    _ZwFreeLocal(rawBuf); // done with raw file

    // repoint PE headers into the mapped copy (rawBuf is freed)
    dosHeader = (IMAGE_DOS_HEADER*)mappedBuf;
    ntHeader = (PIMAGE_NT_HEADERS)((uintptr_t)mappedBuf + dosHeader->e_lfanew);

    // allocate in remote process
    LPVOID remoteBuf = NULL;
    if (PLRing3.allocMethod == PL_ALLOC_MAP_VIEW_OF_SECTION) {
        LARGE_INTEGER secSize;
        secSize.QuadPart = ntHeader->OptionalHeader.SizeOfImage;
        NTSTATUS stSec = ZwApi.ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
            &secSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
        if (!NT_SUCCESS(stSec)) {
            PLLOG("[-] ZwCreateSection failed: 0x%08lX\n", (unsigned long)stSec);
            _ZwFreeLocal(mappedBuf);
            return PL_ERR_ALLOC_REMOTE;
        }
        SIZE_T viewSize = 0;
        stSec = ZwApi.ZwMapViewOfSection(hSection, PLRing3.hTargetProcess,
            &remoteBuf, 0, 0, NULL, &viewSize, 2 /*ViewUnmap*/, 0, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(stSec)) {
            PLLOG("[-] ZwMapViewOfSection (remote) failed: 0x%08lX\n", (unsigned long)stSec);
            ZwApi.ZwClose(hSection);
            hSection = NULL;
            _ZwFreeLocal(mappedBuf);
            return PL_ERR_ALLOC_REMOTE;
        }
    } 
    else if (PLRing3.allocMethod == PL_ALLOC_RWX_HUNT) {
        remoteBuf = _HuntRWXCave(PLRing3.hTargetProcess,
            (SIZE_T)ntHeader->OptionalHeader.SizeOfImage);
        if (!remoteBuf) {
            PLLOG("[-] No suitable RWX cave found for 0x%X bytes\n",
                ntHeader->OptionalHeader.SizeOfImage);
            _ZwFreeLocal(mappedBuf);
            return PL_ERR_ALLOC_REMOTE;
        }
    } 
    else {
        remoteBuf = _ZwAllocRemote(PLRing3.hTargetProcess,
            (SIZE_T)ntHeader->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
        if (!remoteBuf) {
            PLLOG("[-] ZwAllocateVirtualMemory (remote) failed\n");
            _ZwFreeLocal(mappedBuf);
            return PL_ERR_ALLOC_REMOTE;
        }
    }
    PLLOG("[+] Remote alloc: %p\n", remoteBuf);

    uintptr_t delta = (uintptr_t)remoteBuf - (uintptr_t)ntHeader->OptionalHeader.ImageBase;

    // ---- relocations ----
    if (PLRing3.fixRelocations && delta != 0) {
        PLLOG("[*] Fixing relocations (delta=0x%IX)...\n", delta);
        IMAGE_DATA_DIRECTORY BRT = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        IMAGE_BASE_RELOCATION* relocBlock = (IMAGE_BASE_RELOCATION*)((uintptr_t)mappedBuf + BRT.VirtualAddress);
        uintptr_t relocEnd = (uintptr_t)relocBlock + BRT.Size;

        while ((uintptr_t)relocBlock < relocEnd && relocBlock->SizeOfBlock) {
            uintptr_t entryCount = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = (WORD*)((uintptr_t)relocBlock + sizeof(IMAGE_BASE_RELOCATION));

            for (uintptr_t j = 0; j < entryCount; j++) {
                BYTE type = entries[j] >> 12;
                WORD off = entries[j] & 0xFFF;
                if (type == IMAGE_REL_BASED_HIGH) {
                    WORD* patch = (WORD*)((uintptr_t)mappedBuf + relocBlock->VirtualAddress + off);
                    *patch += (WORD)(delta >> 16);
                }
                else if (type == IMAGE_REL_BASED_LOW) {
                    WORD* patch = (WORD*)((uintptr_t)mappedBuf + relocBlock->VirtualAddress + off);
                    *patch += (WORD)(delta & 0xFFFF);
                }
                else if (type == IMAGE_REL_BASED_HIGHADJ) {
                    WORD* patch = (WORD*)((uintptr_t)mappedBuf + relocBlock->VirtualAddress + off);
                    LONG adjusted = ((LONG)*patch << 16) + (SHORT)entries[j + 1];
                    adjusted += (LONG)delta;
                    adjusted += 0x8000;
                    *patch = (WORD)(adjusted >> 16);
                    j++;
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uintptr_t* patch = (uintptr_t*)((uintptr_t)mappedBuf + relocBlock->VirtualAddress + off);
                    *patch += delta;
                }
                else if (type == IMAGE_REL_BASED_DIR64) {
                    ULONGLONG* patch = (ULONGLONG*)((uintptr_t)mappedBuf + relocBlock->VirtualAddress + off);
                    *patch += (ULONGLONG)delta;
                }
            }
            relocBlock = (IMAGE_BASE_RELOCATION*)((uintptr_t)relocBlock + relocBlock->SizeOfBlock);
        }
        PLLOG("[+] Relocations done\n");
    }

    // ---- IAT ----
    if (PLRing3.fixIAT) {
        IMAGE_DATA_DIRECTORY importDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((uintptr_t)mappedBuf + importDir.VirtualAddress);

        if (PLRing3.iatMode == PL_IAT_LOADLIBRARY) {
            PLLOG("[*] IAT fix: LoadLibrary\n");
            while (importDesc->Name) {
                char* modName = (char*)((uintptr_t)mappedBuf + importDesc->Name);
                HMODULE hMod = LoadLibraryA(modName);
                if (!hMod) {
                    PLLOG("  [-] LoadLibraryA('%s') failed: %lu\n", modName, GetLastError());
                    _ZwFreeLocal(mappedBuf);
                    return PL_ERR_IAT_MODULE_NOT_FOUND;
                }
                PLLOG("  [+] %s -> %p\n", modName, (void*)hMod);

                IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((uintptr_t)mappedBuf + importDesc->FirstThunk);
                IMAGE_THUNK_DATA* origThunk = importDesc->OriginalFirstThunk
                    ? (IMAGE_THUNK_DATA*)((uintptr_t)mappedBuf + importDesc->OriginalFirstThunk)
                    : thunk;

                while (origThunk->u1.AddressOfData) {
                    FARPROC func;
                    if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                        func = GetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(origThunk->u1.Ordinal));
                    }
                    else {
                        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)((uintptr_t)mappedBuf + (uintptr_t)origThunk->u1.AddressOfData);
                        func = GetProcAddress(hMod, ibn->Name);
                    }
                    if (!func) {
                        PLLOG("    [-] Function not found in %s\n", modName);
                        _ZwFreeLocal(mappedBuf);
                        return PL_ERR_IAT_FUNC_NOT_FOUND;
                    }
                    thunk->u1.Function = (ULONG_PTR)func;
                    thunk++; origThunk++;
                }
                importDesc++;
            }
            PLLOG("[+] IAT fixed (LoadLibrary)\n");

        }
        else if (PLRing3.iatMode == PL_IAT_READONLY) {
            PLLOG("[*] IAT fix: ReadOnly (remote PEB)\n");
            while (importDesc->Name) {
                char* modName = (char*)((uintptr_t)mappedBuf + importDesc->Name);
                PVOID hMod = RemoteGetModuleBaseFromPEB(PLRing3.hTargetProcess, modName);
                if (!hMod) {
                    PLLOG("  [-] %s not in remote PEB\n", modName);
                    _ZwFreeLocal(mappedBuf);
                    return PL_ERR_IAT_MODULE_NOT_FOUND;
                }
                PLLOG("  [+] %s -> %p\n", modName, hMod);

                IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((uintptr_t)mappedBuf + importDesc->FirstThunk);
                IMAGE_THUNK_DATA* origThunk = importDesc->OriginalFirstThunk
                    ? (IMAGE_THUNK_DATA*)((uintptr_t)mappedBuf + importDesc->OriginalFirstThunk)
                    : thunk;

                while (origThunk->u1.AddressOfData) {
                    FARPROC func;
                    if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                        func = RemoteCustomGetProcAddress(PLRing3.hTargetProcess, hMod, (LPCSTR)IMAGE_ORDINAL(origThunk->u1.Ordinal));
                    }
                    else {
                        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)((uintptr_t)mappedBuf + (uintptr_t)origThunk->u1.AddressOfData);
                        func = RemoteCustomGetProcAddress(PLRing3.hTargetProcess, hMod, ibn->Name);
                    }
                    if (!func) {
                        PLLOG("    [-] Function not found in %s\n", modName);
                        _ZwFreeLocal(mappedBuf);
                        return PL_ERR_IAT_FUNC_NOT_FOUND;
                    }
                    thunk->u1.Function = (ULONG_PTR)func;
                    thunk++; origThunk++;
                }
                importDesc++;
            }
            PLLOG("[+] IAT fixed (ReadOnly)\n");
        }
    }

    // ---- write to remote ----
    if (PLRing3.allocMethod == PL_ALLOC_MAP_VIEW_OF_SECTION) {
        PVOID localView = NULL;
        SIZE_T localViewSize = 0;
        NTSTATUS stMap = ZwApi.ZwMapViewOfSection(hSection, NtCurrentProcess(),
            &localView, 0, 0, NULL, &localViewSize, 2 /*ViewUnmap*/, 0, PAGE_READWRITE);
        if (!NT_SUCCESS(stMap)) {
            PLLOG("[-] ZwMapViewOfSection (local) failed: 0x%08lX\n", (unsigned long)stMap);
            ZwApi.ZwClose(hSection);
            _ZwFreeLocal(mappedBuf);
            return PL_ERR_WRITE_REMOTE;
        }
        memcpy(localView, mappedBuf, ntHeader->OptionalHeader.SizeOfImage);
        ZwApi.ZwUnmapViewOfSection(NtCurrentProcess(), localView);
        ZwApi.ZwClose(hSection);
        PLLOG("[+] Written via shared section\n");
    } 

    else {
        if (!NT_SUCCESS(ZwApi.ZwWriteVirtualMemory(PLRing3.hTargetProcess, remoteBuf, mappedBuf,
            ntHeader->OptionalHeader.SizeOfImage, NULL))) {
            PLLOG("[-] ZwWriteVirtualMemory failed\n");
            _ZwFreeLocal(mappedBuf);
            return PL_ERR_WRITE_REMOTE;
        }
        PLLOG("[+] Written to remote process\n");
    }

    // save before freeing
    DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;
    _ZwFreeLocal(mappedBuf);

    // ---- execute entry point ----
    LPVOID ep = (LPVOID)((uintptr_t)remoteBuf + entryPointRVA);
    return _ExecuteRemote(ep);
}

// ---------------------------------------------------------------
//  Shellcode injection
// ---------------------------------------------------------------
static PL_Result _Shellcode_inject(void)
{
    _ResolveZwApi();

    if (!PLRing3.hTargetProcess) {
        PLLOG("[-] No target process handle\n");
        return PL_ERR_NO_PROCESS;
    }
    if (!PLRing3.shellcodeBytes || PLRing3.shellcodeLen == 0) {
        PLLOG("[-] No shellcode provided\n");
        return PL_ERR_NO_SHELLCODE;
    }

    PLLOG("[*] Shellcode: %lu bytes\n", (unsigned long)PLRing3.shellcodeLen);

    LPVOID remoteBuf = NULL;

    if (PLRing3.allocMethod == PL_ALLOC_MAP_VIEW_OF_SECTION) {
        LARGE_INTEGER secSize;
        secSize.QuadPart = (LONGLONG)PLRing3.shellcodeLen;
        HANDLE hSection = NULL;
        NTSTATUS st = ZwApi.ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
            &secSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
        if (!NT_SUCCESS(st)) {
            PLLOG("[-] ZwCreateSection failed: 0x%08lX\n", (unsigned long)st);
            return PL_ERR_ALLOC_REMOTE;
        }
        PVOID localView = NULL;
        SIZE_T localViewSize = 0;
        st = ZwApi.ZwMapViewOfSection(hSection, NtCurrentProcess(), &localView,
            0, 0, NULL, &localViewSize, 2 /*ViewUnmap*/, 0, PAGE_READWRITE);
        if (!NT_SUCCESS(st)) {
            PLLOG("[-] ZwMapViewOfSection (local) failed: 0x%08lX\n", (unsigned long)st);
            ZwApi.ZwClose(hSection);
            return PL_ERR_ALLOC_REMOTE;
        }
        SIZE_T remoteViewSize = 0;
        st = ZwApi.ZwMapViewOfSection(hSection, PLRing3.hTargetProcess, &remoteBuf,
            0, 0, NULL, &remoteViewSize, 2 /*ViewUnmap*/, 0, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(st)) {
            PLLOG("[-] ZwMapViewOfSection (remote) failed: 0x%08lX\n", (unsigned long)st);
            ZwApi.ZwUnmapViewOfSection(NtCurrentProcess(), localView);
            ZwApi.ZwClose(hSection);
            return PL_ERR_ALLOC_REMOTE;
        }
        memcpy(localView, PLRing3.shellcodeBytes, PLRing3.shellcodeLen);
        ZwApi.ZwUnmapViewOfSection(NtCurrentProcess(), localView);
        ZwApi.ZwClose(hSection);
        PLLOG("[+] Shellcode written via shared section at %p\n", remoteBuf);
    } else {
        if (PLRing3.allocMethod == PL_ALLOC_RWX_HUNT) {
            remoteBuf = _HuntRWXCave(PLRing3.hTargetProcess, PLRing3.shellcodeLen);
            if (!remoteBuf) {
                PLLOG("[-] No suitable RWX cave found for %lu bytes\n",
                    (unsigned long)PLRing3.shellcodeLen);
                return PL_ERR_ALLOC_REMOTE;
            }
            PLLOG("[+] RWX cave: %p\n", remoteBuf);
        } else {
            remoteBuf = _ZwAllocRemote(PLRing3.hTargetProcess,
                PLRing3.shellcodeLen, PAGE_EXECUTE_READWRITE);
            if (!remoteBuf) {
                PLLOG("[-] ZwAllocateVirtualMemory (remote) failed\n");
                return PL_ERR_ALLOC_REMOTE;
            }
            PLLOG("[+] Remote alloc: %p\n", remoteBuf);
        }
        if (!NT_SUCCESS(ZwApi.ZwWriteVirtualMemory(PLRing3.hTargetProcess, remoteBuf,
            PLRing3.shellcodeBytes, PLRing3.shellcodeLen, NULL))) {
            PLLOG("[-] ZwWriteVirtualMemory failed\n");
            return PL_ERR_WRITE_REMOTE;
        }
        PLLOG("[+] Shellcode written\n");
    }

    return _ExecuteRemote(remoteBuf);
}

// ---------------------------------------------------------------
//  Main entry — dispatches based on method
// ---------------------------------------------------------------
PL_Result inject(void)
{
    _ResolveZwApi();

    if (PLRing3.method != PL_METHOD_SHELLCODE && PLRing3.libraryPath[0] == '\0') {
        PLLOG("[-] No DLL path set\n");
        return PL_ERR_NO_DLL_PATH;
    }

    PL_Result res = PL_OK;

    switch (PLRing3.method) {
    case PL_METHOD_SET_WINDOWS_HOOK:
        res = _SetWindowsHookEx_inject();
        break;
    case PL_METHOD_MANUAL_MAP:
        res = _ManualMap_inject();
        break;
    case PL_METHOD_SHELLCODE:
        res = _Shellcode_inject();
        break;
    default:
        PLLOG("[!] Unknown injection method\n");
        break;
    }

    if (res == PL_OK)
        PLLOG("[+] inject() complete\n");
    else
        PLLOG("[-] inject() failed: %s\n", PL_ResultStrings[res]);

    return res;
}