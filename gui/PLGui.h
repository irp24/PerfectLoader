#pragma once
#include <stdarg.h>
#include <commdlg.h>



// Constants
#define WINDOW_WIDTH       640
#define WINDOW_HEIGHT      640
#define MAX_VERTEX_BUFFER  (512 * 1024)
#define MAX_INDEX_BUFFER   (128 * 1024)

// D3D11 globals
static IDXGISwapChain* swap_chain;
static ID3D11Device* device;
static ID3D11DeviceContext* context;
static ID3D11RenderTargetView* rt_view;

// Log scroll offsets (Nuklear type, so stays here) 
static nk_uint log_scroll_x = 0;
static nk_uint log_scroll_y = 0;

// GUI state
char process_name[256] = "ac_client.exe";
char export_name[256] = "";
char shellcode[1024] = "";
int  method_sel = PL_METHOD_MANUAL_MAP;
int  iat_mode_sel = PL_IAT_LOADLIBRARY;
int  exec_method_sel = PL_EXEC_NT_CREATE_THREAD_EX;
int  alloc_method_sel = PL_ALLOC_ZW_ALLOCATE;

// Log buffer — PLLOG writes here via gui_log when pl_log is set
#define LOG_MAX 8192
char  log_buf[LOG_MAX] = "";
int   log_len = 0;

// Process list
typedef struct { DWORD pid; char name[260]; } ProcEntry;
ProcEntry proc_list[2048];
int       proc_count = 0;
int       proc_sel = -1;


// File browser
char dll_path[MAX_PATH] = "";

// Window name lookup — finds the first visible titled window
typedef struct
{
    DWORD pid;
    char title[MAX_PATH];
} _WndSearchCtx;

void gui_log(const char* fmt, ...)
{
    va_list ap;
    char tmp[512];
    int n;
    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (log_len + n + 1 >= LOG_MAX) {
        log_len = 0;
        log_buf[0] = '\0';
    }
    memcpy(log_buf + log_len, tmp, n);
    log_len += n;
    log_buf[log_len] = '\0';
}

 void refresh_process_list()
{
    ResolveZwApi();
    proc_count = 0;
    proc_sel   = -1;
    PBYTE buf = QuerySystemProcessInfo();
    if (!buf)
    {
        return;
    }
    PL_SYSTEM_PROCESS_INFORMATION* entry = (PL_SYSTEM_PROCESS_INFORMATION*)buf;
    while (TRUE) 
    {
        if (proc_count < 2048) 
        {
            proc_list[proc_count].pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
            if (entry->ImageName.Buffer && entry->ImageName.Length > 0) 
            {
                WideCharToMultiByte(CP_ACP, 0, entry->ImageName.Buffer,
                    entry->ImageName.Length / sizeof(WCHAR),
                    proc_list[proc_count].name,
                    sizeof(proc_list[proc_count].name) - 1, NULL, NULL);
                proc_list[proc_count].name[sizeof(proc_list[proc_count].name) - 1] = '\0';
            } 
            else
            {
                strcpy(proc_list[proc_count].name, "[System]");
            }
            proc_count++;
        }
        if (!entry->NextEntryOffset)
        {
            break;
        }
        entry = (PL_SYSTEM_PROCESS_INFORMATION*)((PBYTE)entry + entry->NextEntryOffset);
    }
    ZwFreeLocal(buf);
}

 DWORD find_pid_by_name(const char* name)
{
    ResolveZwApi();
    WCHAR wname[260];
    MultiByteToWideChar(CP_ACP, 0, name, -1, wname, 260);
    PBYTE buf = QuerySystemProcessInfo();
    if (!buf) return 0;
    DWORD found = 0;
    PL_SYSTEM_PROCESS_INFORMATION* entry = (PL_SYSTEM_PROCESS_INFORMATION*)buf;
    while (TRUE)
    {
        if (entry->ImageName.Buffer && entry->ImageName.Length > 0)
        {
            WCHAR entryName[260] = { 0 };
            USHORT copyLen = entry->ImageName.Length;
            if (copyLen > (USHORT)(sizeof(entryName) - sizeof(WCHAR)))
            {
                copyLen = (USHORT)(sizeof(entryName) - sizeof(WCHAR));
            }
            memcpy(entryName, entry->ImageName.Buffer, copyLen);
            if (_wcsicmp(entryName, wname) == 0)
            {
                found = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
                break;
            }
        }
        if (!entry->NextEntryOffset) 
        {
            break;
        }
        entry = (PL_SYSTEM_PROCESS_INFORMATION*)((PBYTE)entry + entry->NextEntryOffset);
    }
    ZwFreeLocal(buf);
    return found;
}

void browse_dll()
{
    OPENFILENAMEA ofn;
    char buf[MAX_PATH] = "";
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = "DLL Files\0*.dll\0All Files\0*.*\0";
    ofn.lpstrFile = buf;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameA(&ofn))
        memcpy(dll_path, buf, MAX_PATH);
}

BOOL CALLBACK _enum_wnd_cb(HWND hwnd, LPARAM lp)
{
    _WndSearchCtx* ctx = (_WndSearchCtx*)lp;
    DWORD wndPid = 0;
    GetWindowThreadProcessId(hwnd, &wndPid);
    if (wndPid == ctx->pid && IsWindowVisible(hwnd) &&
        GetWindowTextA(hwnd, ctx->title, sizeof(ctx->title)) > 0)
        return FALSE;
    return TRUE;
}

const char* findWindowNameFromPath(const char* procName)
{
     char result[MAX_PATH];
    _WndSearchCtx ctx;
    DWORD pid = find_pid_by_name(procName);
    result[0] = '\0';
    if (!pid) return result;
    ctx.pid = pid;
    ctx.title[0] = '\0';
    EnumWindows(_enum_wnd_cb, (LPARAM)&ctx);
    memcpy(result, ctx.title, sizeof(result));
    return result;
}

// Shellcode text parser
int _is_hex(char c) 
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
BYTE _hex_val(char c)
{
    if (c >= '0' && c <= '9') return (BYTE)(c - '0');
    if (c >= 'a' && c <= 'f') return (BYTE)(c - 'a' + 10);
    return (BYTE)(c - 'A' + 10);
}

BYTE* parse_shellcode(const char* src, SIZE_T* outLen)
{
    SIZE_T cap = 512, len = 0;
    BYTE* buf = (BYTE*)malloc(cap);
    const char* p = src;
    *outLen = 0;
    if (!buf) return NULL;

    while (*p) 
    {
        while (*p == ' ' || *p == '\t' || *p == ',' || *p == ';' ||
               *p == '"' || *p == '\'' || *p == '{' || *p == '}' ||
               *p == '\r' || *p == '\n')
            p++;
        if (!*p) break;

        if (p[0] == '\\' && (p[1] == 'x' || p[1] == 'X') && _is_hex(p[2]) && _is_hex(p[3]))
        {
            if (len >= cap) 
            {
                cap *= 2; 
                buf = (BYTE*)realloc(buf, cap);
                if (!buf) return NULL; 
            }
            buf[len++] = (_hex_val(p[2]) << 4) | _hex_val(p[3]); 
            p += 4;
            continue;
        }
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X') && _is_hex(p[2]) && _is_hex(p[3])) 
        {
            if (len >= cap) 
            { 
                cap *= 2;
                buf = (BYTE*)realloc(buf, cap);
                if (!buf) return NULL;
            }
            buf[len++] = (_hex_val(p[2]) << 4) | _hex_val(p[3]);
            p += 4; 
            continue;
        }
        if (_is_hex(p[0]) && _is_hex(p[1])) 
        {
            if (len >= cap) 
            { 
                cap *= 2; 
                buf = (BYTE*)realloc(buf, cap);
                if (!buf) return NULL;
            }
            buf[len++] = (_hex_val(p[0]) << 4) | _hex_val(p[1]); 
            p += 2; 
            continue;
        }
        p++;
    }
    *outLen = len;
    return buf;
}

// Injection glue — wires GUI state into PLRing3 and calls inject()
void do_inject()
{
    ResolveZwApi();

    DWORD pid;
    
    pid = find_pid_by_name(process_name);
    if (!pid)
    { 
        gui_log("[!] '%s' not found\n", process_name);
        return;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) 
    {
        gui_log("[!] OpenProcess failed (%lu). Run as admin?\n", GetLastError());
        return;
    }

    memset(&PLRing3, 0, sizeof(PLRing3));
    strncpy(PLRing3.libraryPath, dll_path, MAX_PATH - 1);
    strncpy(PLRing3.exportedMain, export_name, sizeof(PLRing3.exportedMain) - 1);
    PLRing3.method = (PL_InjectionMethod)method_sel;
    PLRing3.iatMode = (PL_IATMode)iat_mode_sel;
    PLRing3.execMethod = (PL_ExecMethod)exec_method_sel;
    PLRing3.allocMethod = (PL_AllocMethod)alloc_method_sel;
    PLRing3.hTargetProcess = hProc;
    PLRing3.windowName = findWindowNameFromPath(process_name);

    pl_log = gui_log;
    gui_log("[*] Injecting via %s...\n", PL_MethodNames[method_sel]);

    // read DLL from disk 
    WCHAR wPath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, PLRing3.libraryPath, -1, wPath, MAX_PATH);
    UNICODE_STRING ntPath = { 0 };
    RtlDosPathNameToNtPathName_U(wPath, &ntPath, NULL, NULL);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS nts = ZwCreateFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    RtlFreeUnicodeString(&ntPath);

    PL_FILE_STANDARD_INFORMATION fsi;
    IO_STATUS_BLOCK ioQ;
    nts = ZwQueryInformationFile(hFile, &ioQ, &fsi, sizeof(fsi), PL_FileStandardInformation);

    DWORD fileSize = (DWORD)fsi.EndOfFile.LowPart;

    PL_Result  res = PL_OK;
    HANDLE     hSection = NULL;
    LPVOID     raw = NULL, img = NULL, remoteBuf = NULL;
    PIMAGE_NT_HEADERS nth = NULL;

    raw = ZwAllocLocal((SIZE_T)fileSize, PAGE_READWRITE);

    IO_STATUS_BLOCK ioR;
    LARGE_INTEGER off = { 0 };
    nts = ZwReadFile(hFile, NULL, NULL, NULL, &ioR, raw, fileSize, &off, NULL);
    ZwClose(hFile);

    if (!PLRing3.hTargetProcess)
    {
        PLLOG("[-] No target process handle\n");
        return PL_ERR_NO_PROCESS;
    }
    
    if (PLRing3.method == PL_METHOD_SHELLCODE)
    {
        if (!PLRing3.shellcodeBytes || !PLRing3.shellcodeLen)
        {
            PLLOG("[-] No shellcode provided\n");
            return PL_ERR_NO_SHELLCODE;
        }
        PLRing3.shellcodeBytes = parse_shellcode(shellcode, &PLRing3.shellcodeLen);
        if (!PLRing3.shellcodeBytes || PLRing3.shellcodeLen == 0)
        {
            gui_log("[!] No valid bytes in shellcode input\n");
            CloseHandle(hProc); return;
        }
    }
    else
    {
        if (PLRing3.method == PL_METHOD_SET_WINDOWS_HOOK)
        {
            if (PLRing3.exportedMain[0] == '\0')
            {
                PLLOG("[!] No export name specified for SetWindowsHookEx\n");
                return PL_ERR_HOOK_PROC;
            }
        }
        if (PLRing3.libraryPath[0] == '\0')
        {
            PLLOG("[-] No DLL path set\n");
            return PL_ERR_NO_DLL_PATH;
        }

        IMAGE_DOS_HEADER* dh = (IMAGE_DOS_HEADER*)raw;
        if (dh->e_magic != IMAGE_DOS_SIGNATURE)
        {
            gui_log("[-] Not a valid PE (bad DOS signature)\n");
            return;
        }
        nth = (PIMAGE_NT_HEADERS)((uintptr_t)raw + dh->e_lfanew);
        if (nth->Signature != IMAGE_NT_SIGNATURE)
        {
            gui_log("[-] Not a valid PE (bad NT signature)\n");
            return;
        }
    }

    gui_log("[+] ImageBase=0x%IX  EP=0x%08X  Sections=%u  SizeOfImage=0x%X\n",
        (uintptr_t)nth->OptionalHeader.ImageBase, nth->OptionalHeader.AddressOfEntryPoint,
        nth->FileHeader.NumberOfSections, nth->OptionalHeader.SizeOfImage);

    res = inject(hSection, raw, remoteBuf, nth);

    if (PLRing3.shellcodeBytes) 
    { 
        free(PLRing3.shellcodeBytes);
        PLRing3.shellcodeBytes = NULL;
    }
    if (res == PL_OK)
    {
        gui_log("[+] Success!\n");
    }
    CloseHandle(hProc);
}

// D3D11 helpers
static void set_swap_chain_size(int w, int h)
{
    ID3D11Texture2D* bb;
    D3D11_RENDER_TARGET_VIEW_DESC desc;
    HRESULT hr;
    if (rt_view) ID3D11RenderTargetView_Release(rt_view);
    hr = IDXGISwapChain_ResizeBuffers(swap_chain, 0, w, h, DXGI_FORMAT_UNKNOWN, 0);
    if (FAILED(hr)) return;
    memset(&desc, 0, sizeof(desc));
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;
    hr = IDXGISwapChain_GetBuffer(swap_chain, 0, &IID_ID3D11Texture2D, (void**)&bb);
    if (FAILED(hr)) return;
    ID3D11Device_CreateRenderTargetView(device, (ID3D11Resource*)bb, &desc, &rt_view);
    ID3D11Texture2D_Release(bb);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (nk_d3d11_handle_event(hwnd, msg, wp, lp))
        return 0;
    switch (msg) {
    case WM_SIZE:
        if (swap_chain && wp != SIZE_MINIMIZED) {
            set_swap_chain_size(LOWORD(lp), HIWORD(lp));
            nk_d3d11_resize(context, LOWORD(lp), HIWORD(lp));
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// Dark theme
static void set_dark_theme(struct nk_context* ctx)
{
    struct nk_color table[NK_COLOR_COUNT];
    table[NK_COLOR_TEXT] = nk_rgb(210, 210, 210);
    table[NK_COLOR_WINDOW] = nk_rgb(30, 30, 35);
    table[NK_COLOR_HEADER] = nk_rgb(45, 45, 55);
    table[NK_COLOR_BORDER] = nk_rgb(60, 60, 70);
    table[NK_COLOR_BUTTON] = nk_rgb(55, 55, 65);
    table[NK_COLOR_BUTTON_HOVER] = nk_rgb(70, 70, 85);
    table[NK_COLOR_BUTTON_ACTIVE] = nk_rgb(45, 100, 180);
    table[NK_COLOR_TOGGLE] = nk_rgb(50, 50, 60);
    table[NK_COLOR_TOGGLE_HOVER] = nk_rgb(70, 70, 80);
    table[NK_COLOR_TOGGLE_CURSOR] = nk_rgb(45, 100, 180);
    table[NK_COLOR_SELECT] = nk_rgb(45, 45, 55);
    table[NK_COLOR_SELECT_ACTIVE] = nk_rgb(45, 100, 180);
    table[NK_COLOR_SLIDER] = nk_rgb(40, 40, 50);
    table[NK_COLOR_SLIDER_CURSOR] = nk_rgb(45, 100, 180);
    table[NK_COLOR_SLIDER_CURSOR_HOVER] = nk_rgb(60, 120, 200);
    table[NK_COLOR_SLIDER_CURSOR_ACTIVE] = nk_rgb(45, 100, 180);
    table[NK_COLOR_PROPERTY] = nk_rgb(40, 40, 50);
    table[NK_COLOR_EDIT] = nk_rgb(25, 25, 30);
    table[NK_COLOR_EDIT_CURSOR] = nk_rgb(210, 210, 210);
    table[NK_COLOR_COMBO] = nk_rgb(40, 40, 50);
    table[NK_COLOR_CHART] = nk_rgb(40, 40, 50);
    table[NK_COLOR_CHART_COLOR] = nk_rgb(45, 100, 180);
    table[NK_COLOR_CHART_COLOR_HIGHLIGHT] = nk_rgb(255, 0, 0);
    table[NK_COLOR_SCROLLBAR] = nk_rgb(35, 35, 42);
    table[NK_COLOR_SCROLLBAR_CURSOR] = nk_rgb(60, 60, 70);
    table[NK_COLOR_SCROLLBAR_CURSOR_HOVER] = nk_rgb(80, 80, 90);
    table[NK_COLOR_SCROLLBAR_CURSOR_ACTIVE] = nk_rgb(45, 100, 180);
    table[NK_COLOR_TAB_HEADER] = nk_rgb(45, 45, 55);
    nk_style_from_table(ctx, table);
}