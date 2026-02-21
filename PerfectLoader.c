#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "PLGui.h"
 
// Entry point
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
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

    //Main loop
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

         
        //GUI
        
        if (nk_begin(ctx, "PerfectLoader", nk_rect(5, 5, 630, 680),
            NK_WINDOW_BORDER | NK_WINDOW_TITLE))
        {
            // DLL Path
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

            // Target Process
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

            // Process dropdown 
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

            // Injection Method 
            nk_layout_row_dynamic(ctx, 18, 1);
            nk_label(ctx, "Injection Method:", NK_TEXT_LEFT);

            nk_layout_row_dynamic(ctx, 25, PL_METHOD_COUNT);
            for (int i = 0; i < PL_METHOD_COUNT; i++) {
                if (nk_option_label(ctx, PL_MethodNames[i], method_sel == i))
                    method_sel = i;
            }

            
            nk_layout_row_dynamic(ctx, 6, 1);
            nk_spacing(ctx, 1);

            // Options
            nk_layout_row_dynamic(ctx, 18, 1);
            
            nk_label(ctx, "Options:", NK_TEXT_LEFT);

            if (method_sel == PL_METHOD_MANUAL_MAP)
            {
                // IAT sub-options 
                nk_layout_row_dynamic(ctx, 24, PL_IAT_COUNT);
                for (int i = 0; i < PL_IAT_COUNT; i++) {
                    if (nk_option_label(ctx, PL_IATModeNames[i], iat_mode_sel == i))
                        iat_mode_sel = i;
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

            // Export name (only for SetWindowsHookEx) 
            if (method_sel == PL_METHOD_SET_WINDOWS_HOOK) {
                nk_layout_row_dynamic(ctx, 6, 1);
                nk_spacing(ctx, 1);
                nk_layout_row_dynamic(ctx, 18, 1);
                nk_label(ctx, "Exported Hook Proc:", NK_TEXT_LEFT);
                nk_layout_row_dynamic(ctx, 28, 1);
                nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD,
                    export_name, sizeof(export_name), nk_filter_default);
            }
            
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
            

            // INJECT button
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

            // Log header row 
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

            // Auto-scroll to bottom
            {
                static int prev_log_len = 0;
                if (log_len != prev_log_len) {
                    log_scroll_y = (nk_uint)0xFFFFFFFFu; /* clamps to max */
                    prev_log_len = log_len;
                }
            }

            // Scrollable log group 
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

        // render 
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