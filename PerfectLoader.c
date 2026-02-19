/*
 * PerfectLoader — Nuklear D3D11 GUI
 *
 * Visual Studio:
 *   Linker > Input > Additional Dependencies:  d3d11.lib;dxguid.lib;user32.lib;comdlg32.lib
 *   Linker > System > SubSystem:               Windows (/SUBSYSTEM:WINDOWS)
 *
 * Command line (Developer Command Prompt):
 *   cl /D_CRT_SECURE_NO_DEPRECATE /nologo /W3 /O2 /fp:fast
 *      /Fedemo.exe main.c user32.lib dxguid.lib d3d11.lib comdlg32.lib
 *      /link /incremental:no /SUBSYSTEM:WINDOWS
 */

#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <commdlg.h>

 /* ---------------------------------------------------------------
  *  Nuklear config
  * --------------------------------------------------------------- */
#define NK_INCLUDE_FIXED_TYPES
#define NK_INCLUDE_STANDARD_IO
#define NK_INCLUDE_STANDARD_VARARGS
#define NK_INCLUDE_DEFAULT_ALLOCATOR
#define NK_INCLUDE_VERTEX_BUFFER_OUTPUT
#define NK_INCLUDE_FONT_BAKING
#define NK_INCLUDE_DEFAULT_FONT
#define NK_IMPLEMENTATION
#define NK_D3D11_IMPLEMENTATION

#include "../../nuklear.h"
#include "nuklear_d3d11.h"

  /* ---------------------------------------------------------------
   *  Log buffer — PLRing3.h's PLLOG macro writes here via gui_log
   * --------------------------------------------------------------- */
#define LOG_MAX 8192
static char  log_buf[LOG_MAX] = "";
static int   log_len = 0;

static void gui_log(const char* fmt, ...)
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

/* ---------------------------------------------------------------
 *  Injector — set the log callback BEFORE including the header
 * --------------------------------------------------------------- */
#include "PLRing3.h"

 /* ---------------------------------------------------------------
  *  Constants
  * --------------------------------------------------------------- */
#define WINDOW_WIDTH       640
#define WINDOW_HEIGHT      640
#define MAX_VERTEX_BUFFER  (512 * 1024)
#define MAX_INDEX_BUFFER   (128 * 1024)

  /* ---------------------------------------------------------------
   *  D3D11 globals
   * --------------------------------------------------------------- */
static IDXGISwapChain* swap_chain;
static ID3D11Device* device;
static ID3D11DeviceContext* context;
static ID3D11RenderTargetView* rt_view;

/* ---------------------------------------------------------------
 *  Process list
 * --------------------------------------------------------------- */
typedef struct { DWORD pid; char name[260]; } ProcEntry;
static ProcEntry proc_list[2048];
static int       proc_count = 0;
static int       proc_sel = -1;

static void refresh_process_list(void)
{
    _ResolveZwApi();
    proc_count = 0;
    proc_sel   = -1;
    PBYTE buf = _QuerySystemProcessInfo();
    if (!buf) return;
    PL_SYSTEM_PROCESS_INFORMATION* entry = (PL_SYSTEM_PROCESS_INFORMATION*)buf;
    for (;;) {
        if (proc_count < 2048) {
            proc_list[proc_count].pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
            if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
                WideCharToMultiByte(CP_ACP, 0, entry->ImageName.Buffer,
                    entry->ImageName.Length / sizeof(WCHAR),
                    proc_list[proc_count].name,
                    sizeof(proc_list[proc_count].name) - 1, NULL, NULL);
                proc_list[proc_count].name[sizeof(proc_list[proc_count].name) - 1] = '\0';
            } else {
                strcpy(proc_list[proc_count].name, "[System]");
            }
            proc_count++;
        }
        if (!entry->NextEntryOffset) break;
        entry = (PL_SYSTEM_PROCESS_INFORMATION*)((PBYTE)entry + entry->NextEntryOffset);
    }
    _ZwFreeLocal(buf);
}

static DWORD find_pid_by_name(const char* name)
{
    _ResolveZwApi();
    WCHAR wname[260];
    MultiByteToWideChar(CP_ACP, 0, name, -1, wname, 260);
    PBYTE buf = _QuerySystemProcessInfo();
    if (!buf) return 0;
    DWORD found = 0;
    PL_SYSTEM_PROCESS_INFORMATION* entry = (PL_SYSTEM_PROCESS_INFORMATION*)buf;
    for (;;) {
        if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
            WCHAR entryName[260] = { 0 };
            USHORT copyLen = entry->ImageName.Length;
            if (copyLen > (USHORT)(sizeof(entryName) - sizeof(WCHAR)))
                copyLen = (USHORT)(sizeof(entryName) - sizeof(WCHAR));
            memcpy(entryName, entry->ImageName.Buffer, copyLen);
            if (_wcsicmp(entryName, wname) == 0) {
                found = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
                break;
            }
        }
        if (!entry->NextEntryOffset) break;
        entry = (PL_SYSTEM_PROCESS_INFORMATION*)((PBYTE)entry + entry->NextEntryOffset);
    }
    _ZwFreeLocal(buf);
    return found;
}

/* ---------------------------------------------------------------
 *  File browser
 * --------------------------------------------------------------- */
static char dll_path[MAX_PATH] = "";

static void browse_dll(void)
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

/* ---------------------------------------------------------------
 *  GUI state
 * --------------------------------------------------------------- */
static char process_name[256] = "ac_client.exe";
static char export_name[256] = "";
static char shellcode[1024] = "";
static int  method_sel = PL_METHOD_MANUAL_MAP;
static int  iat_mode_sel = PL_IAT_LOADLIBRARY;
static int  opt_fix_iat = 1;
static int  opt_fix_reloc = 1;
static int  exec_method_sel = PL_EXEC_NT_CREATE_THREAD_EX;
static int  alloc_method_sel = PL_ALLOC_ZW_ALLOCATE;

/* Log scroll offsets — persisted across frames */
static nk_uint log_scroll_x = 0;
static nk_uint log_scroll_y = 0;

/* ---------------------------------------------------------------
 *  Window name lookup
 *  Enumerates all top-level windows, matches on PID, and returns
 *  the title of the first visible window found (e.g. "AssaultCube"
 *  for ac_client.exe).  Returns "" when nothing is found.
 * --------------------------------------------------------------- */
typedef struct { DWORD pid; char title[MAX_PATH]; } _WndSearchCtx;

static BOOL CALLBACK _enum_wnd_cb(HWND hwnd, LPARAM lp)
{
    _WndSearchCtx* ctx = (_WndSearchCtx*)lp;
    DWORD wndPid = 0;
    GetWindowThreadProcessId(hwnd, &wndPid);
    if (wndPid == ctx->pid && IsWindowVisible(hwnd) &&
        GetWindowTextA(hwnd, ctx->title, sizeof(ctx->title)) > 0)
        return FALSE; /* stop — found a titled, visible window */
    return TRUE;
}

static const char* findWindowNameFromPath(const char* procName)
{
    static char result[MAX_PATH];
    _WndSearchCtx ctx;
    DWORD pid = find_pid_by_name(procName);
    result[0] = '\0';
    if (!pid) return result;
    ctx.pid   = pid;
    ctx.title[0] = '\0';
    EnumWindows(_enum_wnd_cb, (LPARAM)&ctx);
    memcpy(result, ctx.title, sizeof(result));
    return result;
}

/* ---------------------------------------------------------------
 *  Shellcode text parser
 *  Recognised token formats (freely mixed, any separator between):
 *    \xNN  — C/Python escape   e.g. "\x90\xCC"
 *    0xNN  — C hex literal     e.g. "0x90, 0xCC"
 *    NN    — bare hex pair     e.g. "90 CC" or "90,CC"
 *  Returns a heap-allocated BYTE array; caller must free().
 *  *outLen is set to the number of bytes parsed (0 on failure).
 * --------------------------------------------------------------- */
static int _is_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static BYTE _hex_val(char c)
{
    if (c >= '0' && c <= '9') return (BYTE)(c - '0');
    if (c >= 'a' && c <= 'f') return (BYTE)(c - 'a' + 10);
    return (BYTE)(c - 'A' + 10);
}

static BYTE* parse_shellcode(const char* src, SIZE_T* outLen)
{
    SIZE_T cap = 512, len = 0;
    BYTE* buf = (BYTE*)malloc(cap);
    const char* p = src;
    *outLen = 0;
    if (!buf) return NULL;

    while (*p)
    {
        /* skip whitespace and common separators */
        while (*p == ' ' || *p == '\t' || *p == ',' || *p == ';' ||
               *p == '"' || *p == '\'' || *p == '{' || *p == '}' ||
               *p == '\r' || *p == '\n')
            p++;
        if (!*p) break;

        /* \xNN */
        if (p[0] == '\\' && (p[1] == 'x' || p[1] == 'X') &&
            _is_hex(p[2]) && _is_hex(p[3]))
        {
            if (len >= cap) { cap *= 2; buf = (BYTE*)realloc(buf, cap); if (!buf) return NULL; }
            buf[len++] = (_hex_val(p[2]) << 4) | _hex_val(p[3]);
            p += 4;
            continue;
        }

        /* 0xNN */
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X') &&
            _is_hex(p[2]) && _is_hex(p[3]))
        {
            if (len >= cap) { cap *= 2; buf = (BYTE*)realloc(buf, cap); if (!buf) return NULL; }
            buf[len++] = (_hex_val(p[2]) << 4) | _hex_val(p[3]);
            p += 4;
            continue;
        }

        /* bare hex pair NN */
        if (_is_hex(p[0]) && _is_hex(p[1]))
        {
            if (len >= cap) { cap *= 2; buf = (BYTE*)realloc(buf, cap); if (!buf) return NULL; }
            buf[len++] = (_hex_val(p[0]) << 4) | _hex_val(p[1]);
            p += 2;
            continue;
        }

        p++; /* unrecognised character — skip */
    }

    *outLen = len;
    return buf;
}

/* ---------------------------------------------------------------
 *  Do the injection
 * --------------------------------------------------------------- */
static void do_inject(void)
{
    DWORD pid;

    if (method_sel != PL_METHOD_SHELLCODE && dll_path[0] == '\0') {
        gui_log("[!] No DLL path set\n");
        return;
    }

    if (proc_sel >= 0 && proc_sel < proc_count) {
        pid = proc_list[proc_sel].pid;
        gui_log("[*] Target: %s (PID %lu)\n", proc_list[proc_sel].name, pid);
    }
    else {
        pid = find_pid_by_name(process_name);
        if (!pid) { gui_log("[!] '%s' not found\n", process_name); return; }
        gui_log("[*] Found '%s' -> PID %lu\n", process_name, pid);
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        gui_log("[!] OpenProcess failed (%lu). Run as admin?\n", GetLastError());
        return;
    }

    /* fill the config struct */
    memset(&PLRing3, 0, sizeof(PLRing3));
    strncpy(PLRing3.libraryPath, dll_path, MAX_PATH - 1);
    strncpy(PLRing3.exportedMain, export_name, sizeof(PLRing3.exportedMain) - 1);
    PLRing3.method = (PL_InjectionMethod)method_sel;
    PLRing3.iatMode = (PL_IATMode)iat_mode_sel;
    PLRing3.fixIAT = opt_fix_iat;
    PLRing3.fixRelocations = opt_fix_reloc;
    PLRing3.execMethod = (PL_ExecMethod)exec_method_sel;
    PLRing3.allocMethod = (PL_AllocMethod)alloc_method_sel;
    PLRing3.hTargetProcess = hProc;
    PLRing3.windowName = findWindowNameFromPath(process_name);

    if (method_sel == PL_METHOD_SHELLCODE) {
        PLRing3.shellcodeBytes = parse_shellcode(shellcode, &PLRing3.shellcodeLen);
        if (!PLRing3.shellcodeBytes || PLRing3.shellcodeLen == 0) {
            gui_log("[!] No valid bytes in shellcode input\n");
            CloseHandle(hProc);
            return;
        }
        gui_log("[*] Parsed %lu shellcode bytes\n", (unsigned long)PLRing3.shellcodeLen);
    }

    /* hook our GUI logger in */
    pl_log = gui_log;

    gui_log("[*] Injecting via %s...\n", PL_MethodNames[method_sel]);
    PL_Result res = inject();

    if (PLRing3.shellcodeBytes) {
        free(PLRing3.shellcodeBytes);
        PLRing3.shellcodeBytes = NULL;
    }

    if (res == PL_OK)
        gui_log("[+] Success!\n");

    CloseHandle(hProc);
}

/* ---------------------------------------------------------------
 *  D3D11 helpers
 * --------------------------------------------------------------- */
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

/* ---------------------------------------------------------------
 *  Dark theme
 * --------------------------------------------------------------- */
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

/* ===============================================================
 *  Entry point
 * =============================================================== */
int WINAPI
wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPWSTR lpCmdLine, int nCmdShow)
{
    struct nk_context* ctx;
    WNDCLASSW wc;
    RECT rect = { 0, 0, WINDOW_WIDTH, WINDOW_HEIGHT };
    DWORD style = WS_OVERLAPPEDWINDOW, exstyle = WS_EX_APPWINDOW;
    HWND wnd;
    DXGI_SWAP_CHAIN_DESC scd;
    D3D_FEATURE_LEVEL fl;
    HRESULT hr;
    int running = 1;

    (void)hPrevInstance; (void)lpCmdLine;

    /* Window */
    memset(&wc, 0, sizeof(wc));
    wc.style = CS_DBLCLKS;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.lpszClassName = L"PerfectLoaderClass";
    RegisterClassW(&wc);

    AdjustWindowRectEx(&rect, style, FALSE, exstyle);
    wnd = CreateWindowExW(exstyle, wc.lpszClassName, L"PerfectLoader",
        style | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT,
        rect.right - rect.left, rect.bottom - rect.top,
        NULL, NULL, hInstance, NULL);

    /* D3D11 */
    memset(&scd, 0, sizeof(scd));
    scd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    scd.BufferDesc.RefreshRate.Numerator = 60;
    scd.BufferDesc.RefreshRate.Denominator = 1;
    scd.SampleDesc.Count = 1;
    scd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    scd.BufferCount = 1;
    scd.OutputWindow = wnd;
    scd.Windowed = TRUE;
    scd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE,
        NULL, 0, NULL, 0, D3D11_SDK_VERSION,
        &scd, &swap_chain, &device, &fl, &context);
    if (FAILED(hr)) {
        hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_WARP,
            NULL, 0, NULL, 0, D3D11_SDK_VERSION,
            &scd, &swap_chain, &device, &fl, &context);
        if (FAILED(hr)) {
            MessageBoxW(wnd, L"D3D11 init failed", L"Error", MB_OK);
            return 1;
        }
    }
    set_swap_chain_size(WINDOW_WIDTH, WINDOW_HEIGHT);

    /* Nuklear */
    ctx = nk_d3d11_init(device, WINDOW_WIDTH, WINDOW_HEIGHT,
        MAX_VERTEX_BUFFER, MAX_INDEX_BUFFER);
    {
        struct nk_font_atlas* atlas;
        nk_d3d11_font_stash_begin(&atlas);
        nk_d3d11_font_stash_end();
    }
    set_dark_theme(ctx);

    refresh_process_list();
    gui_log("[*] PerfectLoader ready\n");

    /* ================================================================
     *  Main loop
     * ================================================================ */
    while (running)
    {
        MSG msg;
        nk_input_begin(ctx);
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) running = 0;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        nk_input_end(ctx);

        /* ============================================================
         *  GUI
         * ============================================================ */
        if (nk_begin(ctx, "PerfectLoader", nk_rect(5, 5, 630, 680),
            NK_WINDOW_BORDER | NK_WINDOW_TITLE))
        {
            /* ---- DLL Path ---- */
            nk_layout_row_dynamic(ctx, 18, 1);
            nk_label(ctx, "DLL Path:", NK_TEXT_LEFT);

            nk_layout_row_begin(ctx, NK_STATIC, 28, 2);
            nk_layout_row_push(ctx, 510);
            nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD,
                dll_path, sizeof(dll_path), nk_filter_default);
            nk_layout_row_push(ctx, 90);
            if (nk_button_label(ctx, "Browse..."))
                browse_dll();
            nk_layout_row_end(ctx);

            nk_layout_row_dynamic(ctx, 6, 1);
            nk_spacing(ctx, 1);

            /* ---- Target Process ---- */
            nk_layout_row_dynamic(ctx, 18, 1);
            nk_label(ctx, "Target Process:", NK_TEXT_LEFT);

            nk_layout_row_begin(ctx, NK_STATIC, 28, 2);
            nk_layout_row_push(ctx, 510);
            nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD,
                process_name, sizeof(process_name), nk_filter_default);
            nk_layout_row_push(ctx, 90);
            if (nk_button_label(ctx, "Refresh"))
                refresh_process_list();
            nk_layout_row_end(ctx);

            /* Process dropdown */
            if (proc_count > 0) {
                char combo_lbl[300];
                if (proc_sel >= 0 && proc_sel < proc_count)
                    snprintf(combo_lbl, sizeof(combo_lbl), "%s  [PID %lu]",
                        proc_list[proc_sel].name, proc_list[proc_sel].pid);
                else
                    snprintf(combo_lbl, sizeof(combo_lbl), "-- select from list --");

                nk_layout_row_dynamic(ctx, 28, 1);
                if (nk_combo_begin_label(ctx, combo_lbl, nk_vec2(610, 200))) {
                    nk_layout_row_dynamic(ctx, 22, 1);
                    for (int i = 0; i < proc_count; i++) {
                        char lbl[300];
                        snprintf(lbl, sizeof(lbl), "%-28s  [%lu]",
                            proc_list[i].name, proc_list[i].pid);
                        if (nk_combo_item_label(ctx, lbl, NK_TEXT_LEFT))
                            proc_sel = i;
                    }
                    nk_combo_end(ctx);
                }
            }

            nk_layout_row_dynamic(ctx, 6, 1);
            nk_spacing(ctx, 1);

            /* ---- Injection Method (driven by enum) ---- */
            nk_layout_row_dynamic(ctx, 18, 1);
            nk_label(ctx, "Injection Method:", NK_TEXT_LEFT);

            nk_layout_row_dynamic(ctx, 25, PL_METHOD_COUNT);
            for (int i = 0; i < PL_METHOD_COUNT; i++) {
                if (nk_option_label(ctx, PL_MethodNames[i], method_sel == i))
                    method_sel = i;
            }

            
            nk_layout_row_dynamic(ctx, 6, 1);
            nk_spacing(ctx, 1);

            /* ---- Options ---- */
            nk_layout_row_dynamic(ctx, 18, 1);
            
            nk_label(ctx, "Options:", NK_TEXT_LEFT);

            if (method_sel == PL_METHOD_MANUAL_MAP)
            {
                nk_layout_row_dynamic(ctx, 24, 1);
                nk_checkbox_label(ctx, "Fix Relocations", &opt_fix_reloc);
                nk_checkbox_label(ctx, "Fix IAT", &opt_fix_iat);

                /* IAT sub-options */
                if (opt_fix_iat) {
                    nk_layout_row_dynamic(ctx, 24, PL_IAT_COUNT);
                    for (int i = 0; i < PL_IAT_COUNT; i++) {
                        if (nk_option_label(ctx, PL_IATModeNames[i], iat_mode_sel == i))
                            iat_mode_sel = i;
                    }
                }

                nk_layout_row_dynamic(ctx, 18, 1);
                nk_label(ctx, "Execution Method:", NK_TEXT_LEFT);
                nk_layout_row_dynamic(ctx, 24, 2);
                for (int i = 0; i < PL_EXEC_COUNT; i++) {
                    if (nk_option_label(ctx, PL_ExecMethodNames[i], exec_method_sel == i))
                        exec_method_sel = i;
                }

                nk_layout_row_dynamic(ctx, 18, 1);
                nk_label(ctx, "Allocation Method:", NK_TEXT_LEFT);
                nk_layout_row_dynamic(ctx, 24, PL_ALLOC_COUNT);
                for (int i = 0; i < PL_ALLOC_COUNT; i++) {
                    if (nk_option_label(ctx, PL_AllocMethodNames[i], alloc_method_sel == i))
                        alloc_method_sel = i;
                }

            }

            /* Export name (only for SetWindowsHookEx) */
            if (method_sel == PL_METHOD_SET_WINDOWS_HOOK) {
                nk_layout_row_dynamic(ctx, 6, 1);
                nk_spacing(ctx, 1);
                nk_layout_row_dynamic(ctx, 18, 1);
                nk_label(ctx, "Exported Hook Proc:", NK_TEXT_LEFT);
                nk_layout_row_dynamic(ctx, 28, 1);
                nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD,
                    export_name, sizeof(export_name), nk_filter_default);
            }
            /* Export name (only for SetWindowsHookEx) */
            if (method_sel == PL_METHOD_SHELLCODE) {
                nk_layout_row_dynamic(ctx, 6, 1);
                nk_spacing(ctx, 1);
                nk_layout_row_dynamic(ctx, 18, 1);
                nk_label(ctx, "Shellcode:", NK_TEXT_LEFT);
                nk_layout_row_dynamic(ctx, 28, 1);
                nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD,
                    shellcode, sizeof(shellcode), nk_filter_default);
                nk_layout_row_dynamic(ctx, 18, 1);
                nk_label(ctx, "Execution Method:", NK_TEXT_LEFT);
                nk_layout_row_dynamic(ctx, 24, 2);
                for (int i = 0; i < PL_EXEC_COUNT; i++) {
                    if (nk_option_label(ctx, PL_ExecMethodNames[i], exec_method_sel == i))
                        exec_method_sel = i;
                }
                nk_layout_row_dynamic(ctx, 18, 1);
                nk_label(ctx, "Allocation Method:", NK_TEXT_LEFT);
                nk_layout_row_dynamic(ctx, 24, PL_ALLOC_COUNT);
                for (int i = 0; i < PL_ALLOC_COUNT; i++) {
                    if (nk_option_label(ctx, PL_AllocMethodNames[i], alloc_method_sel == i))
                        alloc_method_sel = i;
                }
            }

            nk_layout_row_dynamic(ctx, 8, 1);
            nk_spacing(ctx, 1);
            

            /* ---- INJECT button (styled blue) ---- */
            nk_layout_row_dynamic(ctx, 38, 1);
            {
                struct nk_style_button btn = ctx->style.button;
                btn.normal = nk_style_item_color(nk_rgb(30, 110, 200));
                btn.hover = nk_style_item_color(nk_rgb(40, 130, 230));
                btn.active = nk_style_item_color(nk_rgb(20, 90, 170));
                btn.text_normal = nk_rgb(255, 255, 255);
                btn.text_hover = nk_rgb(255, 255, 255);
                btn.text_active = nk_rgb(200, 200, 200);
                if (nk_button_label_styled(ctx, &btn, "INJECT"))
                    do_inject();
            }

            nk_layout_row_dynamic(ctx, 6, 1);
            nk_spacing(ctx, 1);

            /* ---- Log header row ---- */
            nk_layout_row_begin(ctx, NK_STATIC, 18, 2);
            nk_layout_row_push(ctx, 540);
            nk_label(ctx, "Log:", NK_TEXT_LEFT);
            nk_layout_row_push(ctx, 60);
            if (nk_button_label(ctx, "Clear")) {
                log_buf[0] = '\0';
                log_len = 0;
                log_scroll_x = 0;
                log_scroll_y = 0;
            }
            nk_layout_row_end(ctx);

            /* Auto-scroll to bottom whenever new log text is appended */
            {
                static int prev_log_len = 0;
                if (log_len != prev_log_len) {
                    log_scroll_y = (nk_uint)0xFFFFFFFFu; /* clamps to max */
                    prev_log_len = log_len;
                }
            }

            /* ---- Scrollable log group ---- */
            nk_layout_row_dynamic(ctx, 120, 1);
            if (nk_group_scrolled_offset_begin(ctx, &log_scroll_x, &log_scroll_y,
                "LogOutput", NK_WINDOW_BORDER))
            {
                const char* p = log_buf;
                while (*p)
                {
                    const char* nl = strchr(p, '\n');
                    int len = nl ? (int)(nl - p) : (int)strlen(p);
                    if (len > 0) {
                        char line[512];
                        if (len >= (int)sizeof(line))
                            len = (int)sizeof(line) - 1;
                        memcpy(line, p, len);
                        line[len] = '\0';
                        nk_layout_row_dynamic(ctx, 16, 1);
                        nk_label(ctx, line, NK_TEXT_LEFT);
                    }
                    if (nl) p = nl + 1;
                    else break;
                }
                nk_group_scrolled_end(ctx);
            }
        }
        nk_end(ctx);

        /* ---- render ---- */
        {
            float clr[4] = { 0.06f, 0.06f, 0.09f, 1.0f };
            ID3D11DeviceContext_ClearRenderTargetView(context, rt_view, clr);
            ID3D11DeviceContext_OMSetRenderTargets(context, 1, &rt_view, NULL);
            nk_d3d11_render(context, NK_ANTI_ALIASING_ON);
            hr = IDXGISwapChain_Present(swap_chain, 1, 0);
            if (hr == DXGI_STATUS_OCCLUDED) Sleep(10);
        }
    }

    ID3D11DeviceContext_ClearState(context);
    nk_d3d11_shutdown();
    ID3D11RenderTargetView_Release(rt_view);
    ID3D11DeviceContext_Release(context);
    ID3D11Device_Release(device);
    IDXGISwapChain_Release(swap_chain);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}