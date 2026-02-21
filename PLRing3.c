#include "PLRing3.h"

struct _PLRing3 PLRing3;

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
    ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

    PEB peb;
    ZwReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);

    FULL_PEB_LDR_DATA ldr;
    ZwReadVirtualMemory(hProcess, peb.Ldr, &ldr, sizeof(ldr), NULL);

    PVOID head = (PVOID)((uintptr_t)peb.Ldr + offsetof(FULL_PEB_LDR_DATA, InLoadOrderModuleList));
    PVOID cur  = ldr.InLoadOrderModuleList.Flink;
    
    while (cur != head)
    {
        LDR_ENTRY_FULL e;
        memset(&e, 0, sizeof(e));
        ZwReadVirtualMemory(hProcess, cur, &e, sizeof(e), NULL);
            
        if (e.BaseDllName.Buffer && e.BaseDllName.Length > 0) 
        {
            WCHAR nameBuf[MAX_PATH] = {0};
            SIZE_T len = e.BaseDllName.Length;
            if (len > (MAX_PATH - 1) * 2)
            {
                len = (MAX_PATH - 1) * 2;
            }
            ZwReadVirtualMemory(hProcess, e.BaseDllName.Buffer, nameBuf, len, NULL);
            if (_wcsicmp(nameBuf, wName) == 0) 
            {
                return e.DllBase;
            }

            
        }
        cur = e.InLoadOrderLinks.Flink;
    }
    return NULL;
}

PVOID RemoteCustomGetProcAddress(HANDLE hProcess, PVOID remoteBase, LPCSTR procName)
{
    IMAGE_DOS_HEADER dos;
    ZwReadVirtualMemory(hProcess, remoteBase, &dos, sizeof(dos), NULL);

    IMAGE_NT_HEADERS nt;
    ZwReadVirtualMemory(hProcess, (uintptr_t)remoteBase + dos.e_lfanew, &nt, sizeof(nt), NULL);

    IMAGE_DATA_DIRECTORY expDataDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    IMAGE_EXPORT_DIRECTORY expDir;
    ZwReadVirtualMemory(hProcess, (uintptr_t)remoteBase + expDataDir.VirtualAddress, &expDir, sizeof(expDir), NULL);

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
        ZwCreateThreadEx(&ht, THREAD_ALL_ACCESS, NULL, PLRing3.hTargetProcess, ep, NULL, 0, 0, 0x1000, 0x100000, NULL);

        PLLOG("[+] Thread created via ZwCreateThreadEx (handle=%p)\n", ht);
        ZwClose(ht);
        return PL_OK;
    }

    case PL_EXEC_QUEUE_USER_APC: 
    {
        PLLOG("[*] ZwQueueApcThread at %p\n", ep);
        DWORD pid = GetProcessId(PLRing3.hTargetProcess);
        PVOID buf = QuerySystemProcessInfo();

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

                    PL_CLIENT_ID cid = { 
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

        PLLOG("[+] APC queued to %d thread(s)\n", queued);
        return PL_OK;
    }

    case PL_EXEC_THREAD_HIJACK: {
        PLLOG("[*] Thread hijack at %p\n", ep);
        DWORD pid = GetProcessId(PLRing3.hTargetProcess);
        PVOID buf = QuerySystemProcessInfo();

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
        ZwSuspendThread(hThread, NULL);

        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_CONTROL;
        ZwGetContextThread(hThread, &ctx);

        #ifdef _WIN64
        ctx.Rip = (DWORD64)ep;
        #else
        ctx.Eip = (DWORD)(uintptr_t)ep;
        #endif

        ZwSetContextThread(hThread, &ctx);
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
    DWORD pid = 0;
    WCHAR wpath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, PLRing3.libraryPath, -1, wpath, MAX_PATH);

    HMODULE lib = LoadLibraryW(wpath);

    if (PLRing3.exportedMain[0] == '\0')
    {
        PLLOG("[!] No export name specified for SetWindowsHookEx\n");
        FreeLibrary(lib);
        return PL_ERR_HOOK_PROC;
    }
    HOOKPROC proc = (HOOKPROC)GetProcAddress(lib, PLRing3.exportedMain);
    HWND hWnd = FindWindowA(NULL, PLRing3.windowName);
    DWORD tid = GetWindowThreadProcessId(hWnd, &pid);
    HHOOK hook = SetWindowsHookExW(WH_GETMESSAGE, proc, lib, tid);

    PLLOG("[+] Hook installed, triggering...\n");
    for (int i = 0; i < 8; i++)
    {
        Sleep(500);
        PostThreadMessage(tid, WM_USER + 432, 0, (LPARAM)hook);
    }
    return PL_OK;
}

PL_Result ManualMapInject(HANDLE hSection, LPVOID raw, PVOID remoteBuf, PIMAGE_NT_HEADERS nth)
{
	// map sections to local memory
    PVOID img = ZwAllocLocal((SIZE_T)nth->OptionalHeader.SizeOfImage, PAGE_READWRITE);

    memcpy(img, raw, nth->OptionalHeader.SizeOfHeaders);
    {
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nth);
        for (WORD i = 0; i < nth->FileHeader.NumberOfSections; i++, sec++)
        {
            if (!sec->SizeOfRawData) 
                continue;
            
            memcpy((PVOID)((uintptr_t)img + sec->VirtualAddress),
                   (PVOID)((uintptr_t)raw + sec->PointerToRawData), sec->SizeOfRawData);
            PLLOG("[+] Section [%.*s]  VA=0x%08X  size=0x%X\n",
                IMAGE_SIZEOF_SHORT_NAME, (char*)sec->Name, sec->VirtualAddress, sec->SizeOfRawData);
        }
    }
    ZwFreeLocal(raw);
    raw = NULL;
    nth = (PIMAGE_NT_HEADERS)((uintptr_t)img + ((IMAGE_DOS_HEADER*)img)->e_lfanew);

    // remote alloc 
    if (PLRing3.allocMethod == PL_ALLOC_MAP_VIEW_OF_SECTION)
    {
        LARGE_INTEGER sz;
        sz.QuadPart = nth->OptionalHeader.SizeOfImage;
        ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sz, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

        SIZE_T viewSz = 0;
        ZwMapViewOfSection(hSection, PLRing3.hTargetProcess, &remoteBuf, 0, 0, NULL, &viewSz, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);

    } 
    else if (PLRing3.allocMethod == PL_ALLOC_RWX_HUNT)
    {
        remoteBuf = HuntRWXCave(PLRing3.hTargetProcess, (SIZE_T)nth->OptionalHeader.SizeOfImage);
        if (!remoteBuf)
        {
            PLLOG("[-] No suitable RWX cave found for 0x%X bytes\n", nth->OptionalHeader.SizeOfImage); 
            PL_Result res = PL_ERR_ALLOC_REMOTE;
            goto done;
        }
    }
    else
    {
        remoteBuf = ZwAllocRemote(PLRing3.hTargetProcess, (SIZE_T)nth->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
    }
    PLLOG("[+] Remote alloc: %p\n", remoteBuf);

    /* relocations */
    {
        uintptr_t delta = (uintptr_t)remoteBuf - (uintptr_t)nth->OptionalHeader.ImageBase;
        if (delta) 
        {
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
    IMAGE_DATA_DIRECTORY impDir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR* id = (IMAGE_IMPORT_DESCRIPTOR*)((uintptr_t)img + impDir.VirtualAddress);

    if (PLRing3.iatMode == PL_IAT_LOADLIBRARY) 
    {
        for (; id->Name; id++)
        {
            char* mod = (char*)((uintptr_t)img + id->Name);
            HMODULE hm = LoadLibraryA(mod);

            PLLOG("  [+] %s -> %p\n", mod, (void*)hm);
            IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((uintptr_t)img + id->FirstThunk);
            IMAGE_THUNK_DATA* orig = id->OriginalFirstThunk ? (IMAGE_THUNK_DATA*)((uintptr_t)img + id->OriginalFirstThunk) : thunk;
            for (; orig->u1.AddressOfData; thunk++, orig++)
            {
                PVOID fn = IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)
                    ? GetProcAddress(hm, (LPCSTR)IMAGE_ORDINAL(orig->u1.Ordinal))
                    : GetProcAddress(hm, ((IMAGE_IMPORT_BY_NAME*)((uintptr_t)img + (uintptr_t)orig->u1.AddressOfData))->Name);

                thunk->u1.Function = (ULONG_PTR)fn;
            }
        }
        PLLOG("[+] IAT fixed (LoadLibrary)\n");
    }
    else if (PLRing3.iatMode == PL_IAT_READONLY)
    {
        for (; id->Name; id++) 
        {
            char* mod = (char*)((uintptr_t)img + id->Name);
            PVOID hm = RemoteGetModuleBaseFromPEB(PLRing3.hTargetProcess, mod);
            if (!hm)
            { 
                PLLOG("  [-] %s not in remote PEB\n", mod);
                PL_Result res = PL_ERR_IAT_MODULE_NOT_FOUND;
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
                    PL_Result res = PL_ERR_IAT_FUNC_NOT_FOUND;
                    goto done;
                }
                thunk->u1.Function = (ULONG_PTR)fn;
            }
        }
        PLLOG("[+] IAT fixed (ReadOnly)\n");
    }

    /* write to remote */
    if (PLRing3.allocMethod == PL_ALLOC_MAP_VIEW_OF_SECTION)
    {
        PVOID lv = NULL;
        SIZE_T lvs = 0;
        ZwMapViewOfSection(hSection, NtCurrentProcess(), &lv, 0, 0, NULL, &lvs, ViewUnmap, 0, PAGE_READWRITE);

        memcpy(lv, img, nth->OptionalHeader.SizeOfImage);
        ZwUnmapViewOfSection(NtCurrentProcess(), lv);
        ZwClose(hSection);
        hSection = NULL;
        PLLOG("[+] Written via shared section\n");
    }
    else 
    {
        ZwWriteVirtualMemory(PLRing3.hTargetProcess, remoteBuf, img, nth->OptionalHeader.SizeOfImage, NULL);

        PLLOG("[+] Written to remote process\n");
    }

    DWORD epRVA = nth->OptionalHeader.AddressOfEntryPoint;
    ZwFreeLocal(img);
    img = NULL;
    PL_Result res = ExecuteRemote((LPVOID)((uintptr_t)remoteBuf + epRVA));

done:
    if (raw) ZwFreeLocal(raw);
    if (img) ZwFreeLocal(img);
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
        ZwCreateSection(&sec, SECTION_ALL_ACCESS, NULL, &sz, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

        PVOID lv = NULL;
        SIZE_T lvs = 0;
        ZwMapViewOfSection(sec, NtCurrentProcess(), &lv, 0, 0, NULL, &lvs, 2, 0, PAGE_READWRITE);

        SIZE_T rvs = 0;
        ZwMapViewOfSection(sec, PLRing3.hTargetProcess, &remoteBuf, 0, 0, NULL, &rvs, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);

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
            PLLOG("[+] Remote alloc: %p\n", remoteBuf);
        }
        ZwWriteVirtualMemory(PLRing3.hTargetProcess, remoteBuf, PLRing3.shellcodeBytes, PLRing3.shellcodeLen, NULL);
        PLLOG("[+] Shellcode written\n");
    }
    return ExecuteRemote(remoteBuf);
}


//public api to call from main
PL_Result inject(HANDLE hSection, LPVOID raw, PVOID remoteBuf, PIMAGE_NT_HEADERS nth)
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
            res = ManualMapInject(hSection, raw, remoteBuf, nth);
            break;
        }
        
        case PL_METHOD_SHELLCODE:      
        {
            res = ShellcodeInject();
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
