#include "PLRing3.h"

struct _PLRing3 PLRing3;

//general utilites
void ResolveZwApi()
{
    static BOOL resolved = FALSE;
    if (resolved) return;

    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!nt) 
    {
        PLLOG("[-] ntdll.dll not found\n");
        return; 
    }

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

PVOID ZwAllocLocal(SIZE_T size, ULONG protect)
{
    PVOID base = NULL;
    SIZE_T sz = size;
    NTSTATUS st = ZwAllocateVirtualMemory(
        NtCurrentProcess(), &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, protect);
    return NT_SUCCESS(st) ? base : NULL;
}

void ZwFreeLocal(PVOID ptr)
{
    SIZE_T sz = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), &ptr, &sz, MEM_RELEASE);
}

PVOID ZwAllocRemote(HANDLE hProcess, SIZE_T size, ULONG protect)
{
    PVOID base = NULL;
    SIZE_T sz = size;
    NTSTATUS st = ZwAllocateVirtualMemory(
        hProcess, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, protect);
    return NT_SUCCESS(st) ? base : NULL;
}

PVOID QuerySystemProcessInfo()
{
    ULONG bufSize = 0x80000;
    PVOID buf = ZwAllocLocal(bufSize, PAGE_READWRITE);
    if (!buf)
    {
        return NULL;
    }
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
            if (!buf)
            {
                return NULL;
            }
        } 
        else 
        {
            ZwFreeLocal(buf);
            return NULL;
        }
    }
}


//mapping utilites
PVOID HuntRWXCave(HANDLE hProcess, SIZE_T need)
{
    MEMORY_BASIC_INFORMATION mbi;
    PVOID addr = NULL;
    while (NT_SUCCESS(ZwQueryVirtualMemory(hProcess, addr, 0, &mbi, sizeof(mbi), NULL)))
    {
        if (mbi.State == MEM_COMMIT
            && (mbi.Protect & PAGE_EXECUTE_READWRITE)
            && !(mbi.Protect & PAGE_GUARD)
            && mbi.RegionSize >= need)
        {
            PBYTE copy = ZwAllocLocal(mbi.RegionSize, PAGE_READWRITE);
            if (copy) 
            {
                SIZE_T got = 0;
                if (NT_SUCCESS(ZwReadVirtualMemory(hProcess, mbi.BaseAddress, copy, mbi.RegionSize, &got))) 
                {
                    SIZE_T run = 0, start = 0;
                    for (SIZE_T i = 0; i < got; i++) 
                    {
                        if (copy[i] == 0x00) 
                        {
                            if (!run)
                            {
                                start = i;
                            }
                            if (++run >= need) 
                            {
                                PVOID hit = (PVOID)((uintptr_t)mbi.BaseAddress + start);
                                ZwFreeLocal(copy);
                                return hit;
                            }
                        } 
                        else run = 0;
                    }
                }
                ZwFreeLocal(copy);
            }
        }
        addr = (PVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        if ((uintptr_t)addr <= (uintptr_t)mbi.BaseAddress)
        {
            break;
        }
    }
    return NULL;
}

PVOID RemoteGetModuleBaseFromPEB(HANDLE hProcess, const char* moduleName)
{
    WCHAR wName[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, moduleName, -1, wName, MAX_PATH);

    PROCESS_BASIC_INFORMATION pbi;
    if (!NT_SUCCESS(ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL)))
    { 
        PLLOG("[-] ZwQueryInformationProcess failed\n");
        return NULL;
    }

    PEB peb;
    if (!NT_SUCCESS(ZwReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)))
    { 
        PLLOG("[-] Failed to read remote PEB\n");
        return NULL;
    }

    FULL_PEB_LDR_DATA ldr;
    if (!NT_SUCCESS(ZwReadVirtualMemory(hProcess, peb.Ldr, &ldr, sizeof(ldr), NULL)))
    { 
        PLLOG("[-] Failed to read remote Ldr\n");
        return NULL;
    }

    PVOID head = (PVOID)((uintptr_t)peb.Ldr + offsetof(FULL_PEB_LDR_DATA, InLoadOrderModuleList));
    PVOID cur  = ldr.InLoadOrderModuleList.Flink;

    while (cur != head)
    {
        LDR_ENTRY_FULL e;
        memset(&e, 0, sizeof(e));
        if (!NT_SUCCESS(ZwReadVirtualMemory(hProcess, cur, &e, sizeof(e), NULL)))
        {
            break;
        }
            
        if (e.BaseDllName.Buffer && e.BaseDllName.Length > 0) 
        {
            WCHAR nameBuf[MAX_PATH] = {0};
            SIZE_T len = e.BaseDllName.Length;
            if (len > (MAX_PATH - 1) * 2)
            {
                len = (MAX_PATH - 1) * 2;
            }
            if (NT_SUCCESS(ZwReadVirtualMemory(hProcess, e.BaseDllName.Buffer, nameBuf, len, NULL)))
            {
                if (_wcsicmp(nameBuf, wName) == 0) 
                {
                    return e.DllBase;
                }

            }
        }
        cur = e.InLoadOrderLinks.Flink;
    }
    return NULL;
}

PVOID RemoteCustomGetProcAddress(HANDLE hProcess, PVOID remoteBase, LPCSTR procName)
{
    IMAGE_DOS_HEADER dos;
    if (!NT_SUCCESS(ZwReadVirtualMemory(hProcess, remoteBase, &dos, sizeof(dos), NULL)))
    {
        return NULL;
    }
    IMAGE_NT_HEADERS nt;
    if (!NT_SUCCESS(ZwReadVirtualMemory(hProcess, (uintptr_t)remoteBase + dos.e_lfanew, &nt, sizeof(nt), NULL)))
    {
        return NULL;
    }
    IMAGE_DATA_DIRECTORY expDataDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDataDir.VirtualAddress) 
    {
        return NULL;
    }

    IMAGE_EXPORT_DIRECTORY expDir;
    if (!NT_SUCCESS(ZwReadVirtualMemory(hProcess, (uintptr_t)remoteBase + expDataDir.VirtualAddress, &expDir, sizeof(expDir), NULL)))
    {
        return NULL;
    }

    uintptr_t funcIdx = (uintptr_t)-1;

    if ((ULONG_PTR)procName >> 16 == 0) 
    {
        // ordinal
        funcIdx = (uintptr_t)(ULONG_PTR)procName - expDir.Base;
        if (funcIdx >= expDir.NumberOfFunctions) return NULL;
    } 
    else 
    {
        for (DWORD i = 0; i < expDir.NumberOfNames; i++)
        {
            DWORD nameRVA = 0;
            ZwReadVirtualMemory(hProcess, (uintptr_t)remoteBase + expDir.AddressOfNames + i * sizeof(DWORD), &nameRVA, sizeof(DWORD), NULL);
            char name[256] = {0};
            ZwReadVirtualMemory(hProcess, (uintptr_t)remoteBase + nameRVA, name, sizeof(name) - 1, NULL);
            if (strcmp(name, procName) == 0)
            {
                WORD ord = 0;
                ZwReadVirtualMemory(hProcess, (uintptr_t)remoteBase + expDir.AddressOfNameOrdinals + i * sizeof(WORD), &ord, sizeof(WORD), NULL);
                funcIdx = ord;
                break;
            }
        }
        if (funcIdx == (uintptr_t)-1) 
        {
            return NULL;
        }
    }

    DWORD funcRVA = 0;
    ZwReadVirtualMemory(hProcess, (uintptr_t)remoteBase + expDir.AddressOfFunctions + funcIdx * sizeof(DWORD), &funcRVA, sizeof(DWORD), NULL);
    if (!funcRVA) 
    {
        return NULL;
    }

    // forwarded claude.ai made it
    if (funcRVA >= expDataDir.VirtualAddress && funcRVA < expDataDir.VirtualAddress + expDataDir.Size) 
    {
        char fwd[256] = {0};
        ZwReadVirtualMemory(hProcess, (uintptr_t)remoteBase + funcRVA, fwd, sizeof(fwd) - 1, NULL);

        char* dot = fwd;
        while (*dot && *dot != '.')
        {
            dot++;
        }
        if (!*dot)
        {
            return NULL;
        }
        *dot = '\0';

        char dll[264];
        int k;
        for (k = 0; fwd[k]; k++) 
        {
            dll[k] = fwd[k];
        }
        int hasDot = 0;
        for (int m = 0; m < k; m++) 
        {
            if (fwd[m] == '.') 
            { 
                hasDot = 1;
                break;
            }
        }
        if (!hasDot) 
        { 
            dll[k++] = '.';
            dll[k++] = 'd';
            dll[k++] = 'l';
            dll[k++] = 'l';
        }
        dll[k] = '\0';

        PVOID fwdMod = RemoteGetModuleBaseFromPEB(hProcess, dll);
        if (!fwdMod) 
        {
            return NULL;
        }

        char* fwdFunc = dot + 1;
        if (fwdFunc[0] == '#')
        {
            ULONG ord = 0;
            for (char* p = fwdFunc + 1; *p >= '0' && *p <= '9'; p++)
            {
                ord = ord * 10 + (*p - '0');
            }
            return RemoteCustomGetProcAddress(hProcess, fwdMod, (LPCSTR)(ULONG_PTR)ord);
        }
        return RemoteCustomGetProcAddress(hProcess, fwdMod, fwdFunc);
    }

    return (PVOID)((uintptr_t)remoteBase + funcRVA);
}


//internal functions
PL_Result ExecuteRemote(PVOID ep)
{
    switch (PLRing3.execMethod)
    {
    case PL_EXEC_NT_CREATE_THREAD_EX: 
    {
        PLLOG("[*] ZwCreateThreadEx at %p\n", ep);
        HANDLE ht = NULL;
        NTSTATUS st = ZwCreateThreadEx(&ht, THREAD_ALL_ACCESS, NULL, PLRing3.hTargetProcess, ep, NULL, 0, 0, 0x1000, 0x100000, NULL);

        if (!NT_SUCCESS(st) || !ht) 
        {
            PLLOG("[-] ZwCreateThreadEx failed: 0x%08lX\n", (unsigned long)st);
            return PL_ERR_THREAD_CREATE;
        }

        PLLOG("[+] Thread created via ZwCreateThreadEx (handle=%p)\n", ht);
        ZwClose(ht);
        return PL_OK;
    }

    case PL_EXEC_QUEUE_USER_APC: 
    {
        PLLOG("[*] ZwQueueApcThread at %p\n", ep);
        DWORD pid = GetProcessId(PLRing3.hTargetProcess);
        PVOID buf = QuerySystemProcessInfo();
        if (!buf) 
        { 
            PLLOG("[-] ZwQuerySystemInformation failed\n");
            return PL_ERR_THREAD_CREATE;
        }

        int queued = 0;
        PL_SYSTEM_PROCESS_INFORMATION* p = (PL_SYSTEM_PROCESS_INFORMATION*)buf;
        while (TRUE)
        {
            if ((DWORD)(ULONG_PTR)p->UniqueProcessId == pid)
            {
                for (ULONG i = 0; i < p->NumberOfThreads; i++)
                {
                    HANDLE ht = NULL;
                    OBJECT_ATTRIBUTES oa;
                    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

                    PL_CLIENT_ID cid = 
                    { 
                        NULL,
                        p->Threads[i].ClientId.UniqueThread 
                    };

                    if (NT_SUCCESS(ZwOpenThread(&ht, THREAD_SET_CONTEXT, &oa, &cid)) && ht) 
                    {
                        ZwQueueApcThread(ht, ep, NULL, NULL, NULL);
                        ZwClose(ht);
                        queued++;
                    }
                }
                break;
            }
            if (!p->NextEntryOffset)
            {
                break;
            }
            p = (PL_SYSTEM_PROCESS_INFORMATION*)((uintptr_t)p + p->NextEntryOffset);
        }
        ZwFreeLocal(buf);
        if (!queued) 
        { 
            PLLOG("[-] No threads found for ZwQueueApcThread\n");
            return PL_ERR_THREAD_CREATE;
        }

        PLLOG("[+] APC queued to %d thread(s)\n", queued);
        return PL_OK;
    }

    case PL_EXEC_THREAD_HIJACK: {
        PLLOG("[*] Thread hijack at %p\n", ep);
        DWORD pid = GetProcessId(PLRing3.hTargetProcess);
        PVOID buf = QuerySystemProcessInfo();
        if (!buf) 
        { 
            PLLOG("[-] ZwQuerySystemInformation failed\n");
            return PL_ERR_THREAD_CREATE;
        }

        HANDLE hThread = NULL;
        PL_SYSTEM_PROCESS_INFORMATION* p = (PL_SYSTEM_PROCESS_INFORMATION*)buf;
        while (TRUE) 
        {
            if ((DWORD)(ULONG_PTR)p->UniqueProcessId == pid) 
            {
                for (ULONG i = 0; i < p->NumberOfThreads && !hThread; i++) 
                {
                    OBJECT_ATTRIBUTES oa;
                    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
                    PL_CLIENT_ID cid = 
                    { 
                        NULL, p->Threads[i].ClientId.UniqueThread 
                    };
                    HANDLE ht = NULL;
                    if (NT_SUCCESS(ZwOpenThread(&ht, THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, &oa, &cid)) && ht)
                    {
                        hThread = ht;
                    }
                }
                break;
            }
            if (!p->NextEntryOffset)
            {
                break;
            }
            p = (PL_SYSTEM_PROCESS_INFORMATION*)((uintptr_t)p + p->NextEntryOffset);
        }
        ZwFreeLocal(buf);

        if (!hThread) 
        {
            PLLOG("[-] No thread found for hijack\n");
            return PL_ERR_THREAD_CREATE;
        }
        if (!NT_SUCCESS(ZwSuspendThread(hThread, NULL))) 
        {
            PLLOG("[-] ZwSuspendThread failed\n");
            ZwClose(hThread);
            return PL_ERR_THREAD_CREATE;
        }
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (!NT_SUCCESS(ZwGetContextThread(hThread, &ctx))) 
        {
            PLLOG("[-] ZwGetContextThread failed\n");
            ZwResumeThread(hThread, NULL);
            ZwClose(hThread);
            return PL_ERR_THREAD_CREATE;
        }

        #ifdef _WIN64
        ctx.Rip = (DWORD64)ep;
        #else
        ctx.Eip = (DWORD)(uintptr_t)ep;
        #endif

        if (!NT_SUCCESS(ZwSetContextThread(hThread, &ctx)))
        {
            PLLOG("[-] ZwSetContextThread failed\n");
            ZwResumeThread(hThread, NULL);
            ZwClose(hThread);
            return PL_ERR_THREAD_CREATE;
        }
        ZwResumeThread(hThread, NULL);
        ZwClose(hThread);
        PLLOG("[+] Thread hijacked, IP redirected to %p\n", ep);
        return PL_OK;
    }

    default:
        return PL_ERR_THREAD_CREATE;
    }
}

PL_Result SetWindowsHookExInject()
{
    WCHAR wpath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, PLRing3.libraryPath, -1, wpath, MAX_PATH);

    HMODULE lib = LoadLibraryW(wpath);
    if (!lib) {
        PLLOG("[!] LoadLibrary failed: %lu\n", GetLastError());
        return PL_ERR_HOOK_LOAD;
    }

    if (PLRing3.exportedMain[0] == '\0')
    {
        PLLOG("[!] No export name specified for SetWindowsHookEx\n");
        FreeLibrary(lib);
        return PL_ERR_HOOK_PROC;
    }
    HOOKPROC proc = (HOOKPROC)GetProcAddress(lib, PLRing3.exportedMain);
    if (!proc)
    {
        PLLOG("[!] Export '%s' not found in DLL\n", PLRing3.exportedMain);
        FreeLibrary(lib);
        return PL_ERR_HOOK_PROC;
    }

    HWND hWnd = FindWindowA(NULL, PLRing3.windowName);
    DWORD pid = 0;
    DWORD tid = GetWindowThreadProcessId(hWnd, &pid);

    HHOOK hook = SetWindowsHookExW(WH_GETMESSAGE, proc, lib, tid);
    if (!hook) 
    {
        PLLOG("[!] SetWindowsHookEx failed: %lu\n", GetLastError());
        FreeLibrary(lib);
        return PL_ERR_HOOK_INSTALL;
    }
    PLLOG("[+] Hook installed, triggering...\n");
    for (int i = 0; i < 8; i++)
    {
        Sleep(500);
        PostThreadMessage(tid, WM_USER + 432, 0, (LPARAM)hook);
    }
    return PL_OK;
}

PL_Result ManualMapInject()
{
    if (!PLRing3.hTargetProcess) 
    {
        PLLOG("[-] No target process handle\n");
        return PL_ERR_NO_PROCESS;
    }

    PL_Result  res = PL_OK;
    HANDLE     hSection = NULL;
    LPVOID     raw = NULL, img = NULL, remoteBuf = NULL;
    PIMAGE_NT_HEADERS nth = NULL;

    /* read DLL from disk */
    WCHAR wPath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, PLRing3.libraryPath, -1, wPath, MAX_PATH);
    UNICODE_STRING ntPath = {0};
    if (!RtlDosPathNameToNtPathName_U(wPath, &ntPath, NULL, NULL)) 
    {
        PLLOG("[-] RtlDosPathNameToNtPathName_U failed\n");
        return PL_ERR_FILE_OPEN;
    }
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS nts = ZwCreateFile(&hFile, FILE_GENERIC_READ, &oa, &iosb,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    RtlFreeUnicodeString(&ntPath);
    if (!NT_SUCCESS(nts))
    {
        PLLOG("[-] ZwCreateFile failed: 0x%08lX\n", (unsigned long)nts);
        return PL_ERR_FILE_OPEN;
    }
    PLLOG("[+] Opened: %s\n", PLRing3.libraryPath);

    PL_FILE_STANDARD_INFORMATION fsi;
    IO_STATUS_BLOCK ioQ;
    nts = ZwQueryInformationFile(hFile, &ioQ, &fsi, sizeof(fsi), PL_FileStandardInformation);
    if (!NT_SUCCESS(nts)) 
    {
        ZwClose(hFile);
        return PL_ERR_FILE_READ;
    }
    DWORD fileSize = (DWORD)fsi.EndOfFile.LowPart;
    PLLOG("[+] File size: %lu bytes\n", fileSize);

    raw = ZwAllocLocal((SIZE_T)fileSize, PAGE_READWRITE);
    if (!raw)
    {
        ZwClose(hFile);
        return PL_ERR_ALLOC_LOCAL;
    }

    IO_STATUS_BLOCK ioR;
    LARGE_INTEGER off = {0};
    nts = ZwReadFile(hFile, NULL, NULL, NULL, &ioR, raw, fileSize, &off, NULL);
    ZwClose(hFile);
    if (!NT_SUCCESS(nts))
    {
        res = PL_ERR_FILE_READ;
        goto done;
    }
    PLLOG("[+] Read %lu bytes\n", (DWORD)ioR.Information);

    /* validate PE */
    {
        IMAGE_DOS_HEADER* dh = (IMAGE_DOS_HEADER*)raw;
        if (dh->e_magic != IMAGE_DOS_SIGNATURE) 
        { 
            PLLOG("[-] Not a valid PE (bad DOS signature)\n");
            res = PL_ERR_PE_INVALID;
            goto done;
        }
        nth = (PIMAGE_NT_HEADERS)((uintptr_t)raw + dh->e_lfanew);
        if (nth->Signature != IMAGE_NT_SIGNATURE)
        { 
            PLLOG("[-] Not a valid PE (bad NT signature)\n");
            res = PL_ERR_PE_INVALID;
            goto done;
        }
    }
    PLLOG("[+] ImageBase=0x%IX  EP=0x%08X  Sections=%u  SizeOfImage=0x%X\n",
        (uintptr_t)nth->OptionalHeader.ImageBase, nth->OptionalHeader.AddressOfEntryPoint,
        nth->FileHeader.NumberOfSections, nth->OptionalHeader.SizeOfImage);

    /* map sections */
    img = ZwAllocLocal((SIZE_T)nth->OptionalHeader.SizeOfImage, PAGE_READWRITE);
    if (!img) 
    { 
        res = PL_ERR_ALLOC_LOCAL;
        goto done;
    }
    memcpy(img, raw, nth->OptionalHeader.SizeOfHeaders);
    {
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nth);
        for (WORD i = 0; i < nth->FileHeader.NumberOfSections; i++, sec++)
        {
            if (!sec->SizeOfRawData) 
            {
                continue;
            }
            memcpy((PVOID)((uintptr_t)img + sec->VirtualAddress),
                   (PVOID)((uintptr_t)raw + sec->PointerToRawData), sec->SizeOfRawData);
            PLLOG("[+] Section [%.*s]  VA=0x%08X  size=0x%X\n",
                IMAGE_SIZEOF_SHORT_NAME, (char*)sec->Name, sec->VirtualAddress, sec->SizeOfRawData);
        }
    }
    ZwFreeLocal(raw);
    raw = NULL;
    nth = (PIMAGE_NT_HEADERS)((uintptr_t)img + ((IMAGE_DOS_HEADER*)img)->e_lfanew);

    /* remote alloc */
    if (PLRing3.allocMethod == PL_ALLOC_MAP_VIEW_OF_SECTION)
    {
        LARGE_INTEGER sz;
        sz.QuadPart = nth->OptionalHeader.SizeOfImage;
        nts = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sz, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
        if (!NT_SUCCESS(nts))
        { 
            PLLOG("[-] ZwCreateSection failed: 0x%08lX\n", (unsigned long)nts);
            res = PL_ERR_ALLOC_REMOTE;
            goto done;
        }
        SIZE_T viewSz = 0;
        nts = ZwMapViewOfSection(hSection, PLRing3.hTargetProcess, &remoteBuf, 0, 0, NULL, &viewSz, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(nts))
        {
            PLLOG("[-] ZwMapViewOfSection (remote) failed: 0x%08lX\n", (unsigned long)nts);
            ZwClose(hSection);
            hSection = NULL;
            res = PL_ERR_ALLOC_REMOTE;
            goto done;
        }
    } 
    else if (PLRing3.allocMethod == PL_ALLOC_RWX_HUNT)
    {
        remoteBuf = HuntRWXCave(PLRing3.hTargetProcess, (SIZE_T)nth->OptionalHeader.SizeOfImage);
        if (!remoteBuf)
        {
            PLLOG("[-] No suitable RWX cave found for 0x%X bytes\n", nth->OptionalHeader.SizeOfImage); 
            res = PL_ERR_ALLOC_REMOTE;
            goto done;
        }
    }
    else
    {
        remoteBuf = ZwAllocRemote(PLRing3.hTargetProcess, (SIZE_T)nth->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
        if (!remoteBuf)
        {
            PLLOG("[-] ZwAllocateVirtualMemory (remote) failed\n");
            res = PL_ERR_ALLOC_REMOTE;
            goto done;
        }
    }
    PLLOG("[+] Remote alloc: %p\n", remoteBuf);

    /* relocations */
    {
        uintptr_t delta = (uintptr_t)remoteBuf - (uintptr_t)nth->OptionalHeader.ImageBase;
        if (PLRing3.fixRelocations && delta) 
        {
            PLLOG("[*] Fixing relocations (delta=0x%IX)...\n", delta);
            IMAGE_DATA_DIRECTORY brt = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            IMAGE_BASE_RELOCATION* blk = (IMAGE_BASE_RELOCATION*)((uintptr_t)img + brt.VirtualAddress);
            uintptr_t end = (uintptr_t)blk + brt.Size;
            while ((uintptr_t)blk < end && blk->SizeOfBlock)
            {
                uintptr_t cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* e = (WORD*)((uintptr_t)blk + sizeof(IMAGE_BASE_RELOCATION));
                for (uintptr_t j = 0; j < cnt; j++) 
                {
                    BYTE t = e[j] >> 12;
                    WORD o = e[j] & 0xFFF;
                    if (t == IMAGE_REL_BASED_HIGH) 
                    {
                        *(WORD*)((uintptr_t)img + blk->VirtualAddress + o) += (WORD)(delta >> 16);
                    }
                    else if (t == IMAGE_REL_BASED_LOW)
                    {
                        *(WORD*)((uintptr_t)img + blk->VirtualAddress + o) += (WORD)(delta & 0xFFFF);
                    }
                    else if (t == IMAGE_REL_BASED_HIGHADJ)
                    {
                        WORD* pp = (WORD*)((uintptr_t)img + blk->VirtualAddress + o);
                        LONG a = ((LONG)*pp << 16) + (SHORT)e[j+1];
                        a += (LONG)delta;
                        a += 0x8000;
                        *pp = (WORD)(a >> 16);
                        j++;
                    }
                    else if (t == IMAGE_REL_BASED_HIGHLOW)
                    {
                        *(uintptr_t*)((uintptr_t)img + blk->VirtualAddress + o) += delta;
                    }
                    else if (t == IMAGE_REL_BASED_DIR64)
                    {
                        *(ULONGLONG*)((uintptr_t)img + blk->VirtualAddress + o) += (ULONGLONG)delta;
                    }
                }
                blk = (IMAGE_BASE_RELOCATION*)((uintptr_t)blk + blk->SizeOfBlock);
            }
            PLLOG("[+] Relocations done\n");
        }
    }

    /* IAT */
    if (PLRing3.fixIAT)
    {
        IMAGE_DATA_DIRECTORY impDir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        IMAGE_IMPORT_DESCRIPTOR* id = (IMAGE_IMPORT_DESCRIPTOR*)((uintptr_t)img + impDir.VirtualAddress);

        if (PLRing3.iatMode == PL_IAT_LOADLIBRARY) 
        {
            PLLOG("[*] IAT fix: LoadLibrary\n");
            for (; id->Name; id++)
            {
                char* mod = (char*)((uintptr_t)img + id->Name);
                HMODULE hm = LoadLibraryA(mod);
                if (!hm) 
                {
                    PLLOG("  [-] LoadLibraryA('%s') failed: %lu\n", mod, GetLastError());
                    res = PL_ERR_IAT_MODULE_NOT_FOUND;
                    goto done;
                }
                PLLOG("  [+] %s -> %p\n", mod, (void*)hm);
                IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((uintptr_t)img + id->FirstThunk);
                IMAGE_THUNK_DATA* orig = id->OriginalFirstThunk ? (IMAGE_THUNK_DATA*)((uintptr_t)img + id->OriginalFirstThunk) : thunk;
                for (; orig->u1.AddressOfData; thunk++, orig++)
                {
                    PVOID fn = IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)
                        ? GetProcAddress(hm, (LPCSTR)IMAGE_ORDINAL(orig->u1.Ordinal))
                        : GetProcAddress(hm, ((IMAGE_IMPORT_BY_NAME*)((uintptr_t)img + (uintptr_t)orig->u1.AddressOfData))->Name);
                    if (!fn)
                    {
                        PLLOG("    [-] Function not found in %s\n", mod);
                        res = PL_ERR_IAT_FUNC_NOT_FOUND;
                        goto done;
                    }
                    thunk->u1.Function = (ULONG_PTR)fn;
                }
            }
            PLLOG("[+] IAT fixed (LoadLibrary)\n");
        }
        else if (PLRing3.iatMode == PL_IAT_READONLY)
        {
            PLLOG("[*] IAT fix: ReadOnly (remote PEB)\n");
            for (; id->Name; id++) 
            {
                char* mod = (char*)((uintptr_t)img + id->Name);
                PVOID hm = RemoteGetModuleBaseFromPEB(PLRing3.hTargetProcess, mod);
                if (!hm)
                { 
                    PLLOG("  [-] %s not in remote PEB\n", mod);
                    res = PL_ERR_IAT_MODULE_NOT_FOUND;
                    goto done;
                }
                PLLOG("  [+] %s -> %p\n", mod, hm);
                IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((uintptr_t)img + id->FirstThunk);
                IMAGE_THUNK_DATA* orig = id->OriginalFirstThunk ? (IMAGE_THUNK_DATA*)((uintptr_t)img + id->OriginalFirstThunk) : thunk;
                for (; orig->u1.AddressOfData; thunk++, orig++) 
                {
                    PVOID fn = IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)
                        ? RemoteCustomGetProcAddress(PLRing3.hTargetProcess, hm, (LPCSTR)IMAGE_ORDINAL(orig->u1.Ordinal))
                        : RemoteCustomGetProcAddress(PLRing3.hTargetProcess, hm, ((IMAGE_IMPORT_BY_NAME*)((uintptr_t)img + (uintptr_t)orig->u1.AddressOfData))->Name);
                    if (!fn)
                    {
                        PLLOG("    [-] Function not found in %s\n", mod);
                        res = PL_ERR_IAT_FUNC_NOT_FOUND;
                        goto done;
                    }
                    thunk->u1.Function = (ULONG_PTR)fn;
                }
            }
            PLLOG("[+] IAT fixed (ReadOnly)\n");
        }
    }

    /* write to remote */
    if (PLRing3.allocMethod == PL_ALLOC_MAP_VIEW_OF_SECTION)
    {
        PVOID lv = NULL;
        SIZE_T lvs = 0;
        nts = ZwMapViewOfSection(hSection, NtCurrentProcess(), &lv, 0, 0, NULL, &lvs, ViewUnmap, 0, PAGE_READWRITE);
        if (!NT_SUCCESS(nts))
        { 
            PLLOG("[-] ZwMapViewOfSection (local) failed: 0x%08lX\n", (unsigned long)nts);
            ZwClose(hSection);
            hSection = NULL;
            res = PL_ERR_WRITE_REMOTE;
            goto done;
        }
        memcpy(lv, img, nth->OptionalHeader.SizeOfImage);
        ZwUnmapViewOfSection(NtCurrentProcess(), lv);
        ZwClose(hSection);
        hSection = NULL;
        PLLOG("[+] Written via shared section\n");
    }
    else 
    {
        nts = ZwWriteVirtualMemory(PLRing3.hTargetProcess, remoteBuf, img, nth->OptionalHeader.SizeOfImage, NULL);
        if (!NT_SUCCESS(nts)) 
        {
            PLLOG("[-] ZwWriteVirtualMemory failed\n");
            res = PL_ERR_WRITE_REMOTE;
            goto done;
        }
        PLLOG("[+] Written to remote process\n");
    }

    {
        DWORD epRVA = nth->OptionalHeader.AddressOfEntryPoint;
        ZwFreeLocal(img);
        img = NULL;
        res = ExecuteRemote((LPVOID)((uintptr_t)remoteBuf + epRVA));
    }

done:
    if (raw) 
    {
        ZwFreeLocal(raw);
    }
    if (img) 
    {
        ZwFreeLocal(img);
    }
    return res;
}

PL_Result ShellcodeInject()
{
    if (!PLRing3.hTargetProcess)
    { 
        PLLOG("[-] No target process handle\n");
        return PL_ERR_NO_PROCESS;
    }
    if (!PLRing3.shellcodeBytes || !PLRing3.shellcodeLen)
    {
        PLLOG("[-] No shellcode provided\n");
        return PL_ERR_NO_SHELLCODE;
    }

    PLLOG("[*] Shellcode: %lu bytes\n", (unsigned long)PLRing3.shellcodeLen);
    LPVOID remoteBuf = NULL;

    if (PLRing3.allocMethod == PL_ALLOC_MAP_VIEW_OF_SECTION)
    {
        LARGE_INTEGER sz;
        sz.QuadPart = (LONGLONG)PLRing3.shellcodeLen;
        HANDLE sec = NULL;
        NTSTATUS st = ZwCreateSection(&sec, SECTION_ALL_ACCESS, NULL, &sz, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
        if (!NT_SUCCESS(st)) 
        {
            PLLOG("[-] ZwCreateSection failed: 0x%08lX\n", (unsigned long)st);
            return PL_ERR_ALLOC_REMOTE;
        }

        PVOID lv = NULL;
        SIZE_T lvs = 0;
        st = ZwMapViewOfSection(sec, NtCurrentProcess(), &lv, 0, 0, NULL, &lvs, 2, 0, PAGE_READWRITE);
        if (!NT_SUCCESS(st)) 
        {
            PLLOG("[-] ZwMapViewOfSection (local) failed: 0x%08lX\n", (unsigned long)st);
            ZwClose(sec);
            return PL_ERR_ALLOC_REMOTE;
        }

        SIZE_T rvs = 0;
        st = ZwMapViewOfSection(sec, PLRing3.hTargetProcess, &remoteBuf, 0, 0, NULL, &rvs, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(st))
        {
            PLLOG("[-] ZwMapViewOfSection (remote) failed: 0x%08lX\n", (unsigned long)st);
            ZwUnmapViewOfSection(NtCurrentProcess(), lv);
            ZwClose(sec);
            return PL_ERR_ALLOC_REMOTE;
        }

        memcpy(lv, PLRing3.shellcodeBytes, PLRing3.shellcodeLen);
        ZwUnmapViewOfSection(NtCurrentProcess(), lv);
        ZwClose(sec);
        PLLOG("[+] Shellcode written via shared section at %p\n", remoteBuf);
    } 
    else {
        if (PLRing3.allocMethod == PL_ALLOC_RWX_HUNT) 
        {
            remoteBuf = HuntRWXCave(PLRing3.hTargetProcess, PLRing3.shellcodeLen);
            if (!remoteBuf) 
            { 
                PLLOG("[-] No suitable RWX cave found for %lu bytes\n", (unsigned long)PLRing3.shellcodeLen);
                return PL_ERR_ALLOC_REMOTE;
            }
            PLLOG("[+] RWX cave: %p\n", remoteBuf);
        }
        else
        {
            remoteBuf = ZwAllocRemote(PLRing3.hTargetProcess, PLRing3.shellcodeLen, PAGE_EXECUTE_READWRITE);
            if (!remoteBuf) 
            {
                PLLOG("[-] ZwAllocateVirtualMemory (remote) failed\n");
                return PL_ERR_ALLOC_REMOTE;
            }
            PLLOG("[+] Remote alloc: %p\n", remoteBuf);
        }
        if (!NT_SUCCESS(ZwWriteVirtualMemory(PLRing3.hTargetProcess, remoteBuf, PLRing3.shellcodeBytes, PLRing3.shellcodeLen, NULL))) 
        {
            PLLOG("[-] ZwWriteVirtualMemory failed\n");
            return PL_ERR_WRITE_REMOTE;
        }
        PLLOG("[+] Shellcode written\n");
    }
    return ExecuteRemote(remoteBuf);
}


//public api to call from main
PL_Result inject()
{
    ResolveZwApi();
    if (PLRing3.method != PL_METHOD_SHELLCODE && PLRing3.libraryPath[0] == '\0')
    {
        PLLOG("[-] No DLL path set\n");
        return PL_ERR_NO_DLL_PATH;
    }

    PL_Result res = PL_OK;
    switch (PLRing3.method)
    {
        case PL_METHOD_SET_WINDOWS_HOOK: 
        {
            res = SetWindowsHookExInject();
            break;
        }
        
        case PL_METHOD_MANUAL_MAP:    
        {
            res = ManualMapInject();
            break;
        }
        
        case PL_METHOD_SHELLCODE:      
        {
            res = ShellcodeInject();
            break;
        }
        default:
        {
            PLLOG("[!] Unknown injection method\n");
            break;
        }
        
    }

    if (res == PL_OK)
    {
        PLLOG("[+] inject() complete\n");
    }
    else 
    {
        PLLOG("[-] inject() failed: %s\n", PL_ResultStrings[res]);
    }
    return res;
}
