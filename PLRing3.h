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
};

// ---------------------------------------------------------------
//  Config struct
// ---------------------------------------------------------------
struct _PLRing3 {
    char                libraryPath[MAX_PATH];  // fixed buffer, safe to edit from GUI
    char                exportedMain[256];       // for SetWindowsHookEx

    PL_InjectionMethod  method;
    PL_IATMode          iatMode;

    BOOL                fixIAT;
    BOOL                fixRelocations;
    BOOL                createRemoteThread;

    HANDLE              hTargetProcess;
} PLRing3;

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
    WCHAR wName[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, moduleName, -1, wName, MAX_PATH);

    PROCESS_BASIC_INFORMATION pbi;
    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {
        PLLOG("[-] NtQueryInformationProcess failed\n");
        return NULL;
    }

    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        PLLOG("[-] Failed to read remote PEB\n");
        return NULL;
    }

    FULL_PEB_LDR_DATA ldr;
    if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(ldr), NULL)) {
        PLLOG("[-] Failed to read remote Ldr\n");
        return NULL;
    }

    PVOID headRemote = (PVOID)((PBYTE)peb.Ldr + offsetof(FULL_PEB_LDR_DATA, InLoadOrderModuleList));
    PVOID entryRemote = ldr.InLoadOrderModuleList.Flink;

    while (entryRemote != headRemote) {
        LDR_ENTRY_FULL entry;
        memset(&entry, 0, sizeof(entry));
        if (!ReadProcessMemory(hProcess, entryRemote, &entry, sizeof(entry), NULL))
            break;

        if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0) {
            WCHAR nameBuf[MAX_PATH];
            memset(nameBuf, 0, sizeof(nameBuf));
            SIZE_T readLen = entry.BaseDllName.Length;
            if (readLen > (MAX_PATH - 1) * 2)
                readLen = (MAX_PATH - 1) * 2;
            if (ReadProcessMemory(hProcess, entry.BaseDllName.Buffer, nameBuf, readLen, NULL)) {
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
    IMAGE_DOS_HEADER dos;
    if (!ReadProcessMemory(hProcess, remoteBase, &dos, sizeof(dos), NULL))
        return NULL;

    IMAGE_NT_HEADERS nt;
    if (!ReadProcessMemory(hProcess, (PBYTE)remoteBase + dos.e_lfanew, &nt, sizeof(nt), NULL))
        return NULL;

    IMAGE_DATA_DIRECTORY expDataDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDataDir.VirtualAddress)
        return NULL;

    IMAGE_EXPORT_DIRECTORY expDir;
    if (!ReadProcessMemory(hProcess, (PBYTE)remoteBase + expDataDir.VirtualAddress, &expDir, sizeof(expDir), NULL))
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
            ReadProcessMemory(hProcess, (PBYTE)remoteBase + expDir.AddressOfNames + i * sizeof(DWORD), &nameRVA, sizeof(DWORD), NULL);
            char exportedName[256];
            memset(exportedName, 0, sizeof(exportedName));
            ReadProcessMemory(hProcess, (PBYTE)remoteBase + nameRVA, exportedName, sizeof(exportedName) - 1, NULL);
            if (strcmp(exportedName, procName) == 0) {
                WORD nameOrd = 0;
                ReadProcessMemory(hProcess, (PBYTE)remoteBase + expDir.AddressOfNameOrdinals + i * sizeof(WORD), &nameOrd, sizeof(WORD), NULL);
                funcIdx = nameOrd;
                break;
            }
        }
        if (funcIdx == (uintptr_t)-1)
            return NULL;
    }

    DWORD funcRVA = 0;
    ReadProcessMemory(hProcess, (PBYTE)remoteBase + expDir.AddressOfFunctions + funcIdx * sizeof(DWORD), &funcRVA, sizeof(DWORD), NULL);
    if (!funcRVA)
        return NULL;

    // forwarded export handling
    if (funcRVA >= expDataDir.VirtualAddress && funcRVA < expDataDir.VirtualAddress + expDataDir.Size) {
        char fwdSrc[256];
        memset(fwdSrc, 0, sizeof(fwdSrc));
        ReadProcessMemory(hProcess, (PBYTE)remoteBase + funcRVA, fwdSrc, sizeof(fwdSrc) - 1, NULL);

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
//  SetWindowsHookEx injection
// ---------------------------------------------------------------
static PL_Result _SetWindowsHookEx_inject(void)
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

    HWND hWnd = FindWindowA(NULL, "AssaultCube");

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
    if (!PLRing3.hTargetProcess) {
        PLLOG("[-] No target process handle\n");
        return PL_ERR_NO_PROCESS;
    }

    // open the DLL file
    HANDLE hFile = CreateFileA(PLRing3.libraryPath, GENERIC_READ, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PLLOG("[-] CreateFileA failed: %lu\n", GetLastError());
        return PL_ERR_FILE_OPEN;
    }
    PLLOG("[+] Opened: %s\n", PLRing3.libraryPath);

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return PL_ERR_FILE_READ;
    }
    PLLOG("[+] File size: %lu bytes\n", fileSize);

    LPVOID rawBuf = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rawBuf) { CloseHandle(hFile); return PL_ERR_ALLOC_LOCAL; }

    DWORD bytesRead;
    BOOL readOk = ReadFile(hFile, rawBuf, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    if (!readOk) {
        VirtualFree(rawBuf, 0, MEM_RELEASE);
        return PL_ERR_FILE_READ;
    }
    PLLOG("[+] Read %lu bytes\n", bytesRead);

    // parse PE
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)rawBuf;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        PLLOG("[-] Not a valid PE (bad DOS signature)\n");
        VirtualFree(rawBuf, 0, MEM_RELEASE);
        return PL_ERR_PE_INVALID;
    }

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((uintptr_t)rawBuf + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        PLLOG("[-] Not a valid PE (bad NT signature)\n");
        VirtualFree(rawBuf, 0, MEM_RELEASE);
        return PL_ERR_PE_INVALID;
    }

    PLLOG("[+] ImageBase=0x%IX  EP=0x%08X  Sections=%u  SizeOfImage=0x%X\n",
        (uintptr_t)ntHeader->OptionalHeader.ImageBase,
        ntHeader->OptionalHeader.AddressOfEntryPoint,
        ntHeader->FileHeader.NumberOfSections,
        ntHeader->OptionalHeader.SizeOfImage);

    // map sections locally
    LPVOID mappedBuf = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mappedBuf) {
        VirtualFree(rawBuf, 0, MEM_RELEASE);
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

    VirtualFree(rawBuf, 0, MEM_RELEASE); // done with raw file

    // repoint PE headers into the mapped copy (rawBuf is freed)
    dosHeader = (IMAGE_DOS_HEADER*)mappedBuf;
    ntHeader = (PIMAGE_NT_HEADERS)((uintptr_t)mappedBuf + dosHeader->e_lfanew);

    // allocate in remote process
    LPVOID remoteBuf = VirtualAllocEx(PLRing3.hTargetProcess, NULL,
        ntHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBuf) {
        PLLOG("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        VirtualFree(mappedBuf, 0, MEM_RELEASE);
        return PL_ERR_ALLOC_REMOTE;
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
                    VirtualFree(mappedBuf, 0, MEM_RELEASE);
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
                        VirtualFree(mappedBuf, 0, MEM_RELEASE);
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
                    VirtualFree(mappedBuf, 0, MEM_RELEASE);
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
                        VirtualFree(mappedBuf, 0, MEM_RELEASE);
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
    if (!WriteProcessMemory(PLRing3.hTargetProcess, remoteBuf, mappedBuf,
        ntHeader->OptionalHeader.SizeOfImage, NULL)) {
        PLLOG("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFree(mappedBuf, 0, MEM_RELEASE);
        return PL_ERR_WRITE_REMOTE;
    }
    PLLOG("[+] Written to remote process\n");

    // save before freeing
    DWORD entryPointRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;
    VirtualFree(mappedBuf, 0, MEM_RELEASE);

    // ---- execute entry point ----
    if (PLRing3.createRemoteThread) {
        LPVOID ep = (LPVOID)((uintptr_t)remoteBuf + entryPointRVA);
        PLLOG("[*] Creating remote thread at %p\n", ep);
        HANDLE hThread = CreateRemoteThread(PLRing3.hTargetProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)ep, NULL, 0, NULL);
        if (!hThread) {
            PLLOG("[-] CreateRemoteThread failed: %lu\n", GetLastError());
            return PL_ERR_THREAD_CREATE;
        }
        PLLOG("[+] Remote thread created (handle=%p)\n", hThread);
        CloseHandle(hThread);
    }

    return PL_OK;
}

// ---------------------------------------------------------------
//  Main entry — dispatches based on method
// ---------------------------------------------------------------
PL_Result inject(void)
{
    if (PLRing3.libraryPath[0] == '\0') {
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
        PLLOG("[!] Shellcode injection not implemented yet\n");
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