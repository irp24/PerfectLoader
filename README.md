<div align="center">

# PerfectLoader

<p>A Windows DLL and shellcode injection tool with a Direct3D 11 GUI, built entirely in C.<br>
All NT syscall wrappers are resolved dynamically at runtime from <code>ntdll.dll</code> — no static imports of Zw/Nt APIs.</p>

![Platform](https://img.shields.io/badge/platform-Windows-0078d4?style=flat-square&logo=windows)
![Language](https://img.shields.io/badge/language-C-00599c?style=flat-square&logo=c)
![GUI](https://img.shields.io/badge/GUI-Direct3D%2011%20%2B%20Nuklear-black?style=flat-square)
![Arch](https://img.shields.io/badge/arch-x64%20%7C%20x86-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/license-Educational-red?style=flat-square)

</div>

---

## ✨ Features at a Glance

> Mix and match injection, execution, and allocation strategies independently from the GUI.

<table>
<tr>
<td valign="top" width="33%">

### 🧬 Injection
- Manual Map (reflective PE)
- SetWindowsHookEx
- Shellcode

</td>
<td valign="top" width="33%">

### ⚡ Execution
- NtCreateThreadEx
- QueueUserAPC
- Thread Hijack

</td>
<td valign="top" width="33%">

### 🗺️ Allocation
- ZwAllocateVirtualMemory
- NtMapViewOfSection
- RWX Cave Hunt

</td>
</tr>
</table>

---

## 🏗️ Architecture

```
PerfectLoader/
├── PerfectLoader.c     — WinMain, D3D11 setup, Nuklear main loop
├── PLGui.h             — GUI state, process list, shellcode parser, injection glue (do_inject)
├── PLRing3.h           — Config struct, enums, NT type definitions, Zw function pointer declarations
├── PLRing3.c           — Injection engine: ResolveZwApi, ManualMapInject, ShellcodeInject,
│                         SetWindowsHookExInject, ExecuteRemote, helper utilities
├── nuklear.h           — Nuklear immediate-mode GUI library
└── nuklear_d3d11.h     — Nuklear Direct3D 11 backend
```

### `PLRing3` Config Struct

The GUI wires everything automatically. To use the engine headlessly, populate the global `PLRing3` struct and call `inject()`:

```c
PLRing3.hTargetProcess  = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
PLRing3.method          = PL_METHOD_MANUAL_MAP;
PLRing3.execMethod      = PL_EXEC_NT_CREATE_THREAD_EX;
PLRing3.allocMethod     = PL_ALLOC_ZW_ALLOCATE;
PLRing3.fixRelocations  = TRUE;
PLRing3.fixIAT          = TRUE;
PLRing3.iatMode         = PL_IAT_LOADLIBRARY;
strncpy(PLRing3.libraryPath, "C:\\path\\to\\payload.dll", MAX_PATH - 1);

inject();
```

The logging sink defaults to `printf`. Redirect it to your own function before calling `inject()`:

```c
pl_log = my_log_function;
```

---

## 🔨 Building

Open `PerfectLoader.sln` and build in **Release** or **Debug** configuration.

> [!NOTE]
> The project links against `ntdll.lib` for type resolution only. All actual Zw/Nt function addresses are resolved at runtime via `GetProcAddress` through `ResolveZwApi()`.

---

## 🚀 Usage

1. Run **`PerfectLoader.exe`** as **Administrator**
2. Enter or browse for the **DLL path** *(not required for shellcode mode)*
3. Select the **Target Process** from the dropdown or type the process name
4. Choose an **Injection Method**, **Execution Method**, and **Allocation Method**
5. **SetWindowsHookEx only** — enter the name of the exported hook procedure in your DLL
6. **Shellcode only** — paste your payload in `\xNN`, `0xNN`, or bare hex format
7. Click **INJECT**

---

## ⚠️ Disclaimer

This project is intended for **educational and research purposes only** (e.g., malware analysis, security research in controlled environments). Do not use against systems you do not own or have explicit permission to test.
