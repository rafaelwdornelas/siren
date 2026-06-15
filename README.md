# Siren — Phantom Section Loader

> A clean, open-source implementation of section-based DLL injection for Windows x64.
> CET-ready. No admin. No WriteProcessMemory. Fire-and-forget.

**Author:** Rafael Dornelas  
**License:** MIT

---

## Overview

**Siren** implements a technique called **Phantom Section Loader** — an in-memory DLL injection method that combines pagefile-backed section mapping with a reflective PE loader.

The payload is delivered through a shared NT section object (no `WriteProcessMemory`, no `VirtualAllocEx`), and execution is triggered via `NtCreateThreadEx`. The injector can close all handles and exit immediately — the payload runs independently inside the target process.

### Properties

| Property | Description |
|---|---|
| **CET-Ready** | All indirect call targets begin with `endbr64`. Prepared for future IBT enforcement on Windows. |
| **Zero WriteProcessMemory** | Payload delivered via `NtCreateSection` + `NtMapViewOfSection` (shared section). |
| **Zero VirtualAllocEx** | Memory in the target is allocated by the NT memory manager through section mapping. |
| **No Admin / No UAC** | Works as a standard user. No `SeDebugPrivilege` needed. |
| **Fire-and-Forget** | Injector exits immediately after injection. Payload runs independently. |
| **Forwarder-Safe Imports** | Uses `GetProcAddress` for IAT resolution, correctly handling API forwarders (e.g., `CreateFileW → KERNELBASE`). |

---

## Prior Art & Contribution

Siren builds on well-established techniques from the security research community:

| Component | Prior Art |
|---|---|
| Section mapping without WPM | [Barakat, 2018](https://gist.github.com/Barakat/1dccd8e5336c660b18eeda46b86113ce); [SafeBreach / Pinjectra, Black Hat 2019](https://github.com/SafeBreach-Labs/pinjectra) |
| Reflective DLL injection | [Stephen Fewer, 2008](https://github.com/stephenfewer/ReflectiveDLLInjection) |
| Section delivery + manual PE loading | [Hunt & Hackett, 2022](https://www.huntandhackett.com/blog/concealed-code-execution-techniques-and-detection) |
| PEB walk + NtCreateThreadEx | Documented extensively since ~2017 |

### What Siren contributes

1. **Open-source reference implementation** — A clean, well-documented C library integrating section injection + reflective PE loader with a simple `siren_inject()` API.
2. **API forwarder handling** — Documents and solves the forwarder problem (e.g., `kernel32!CreateFileW` → `KERNELBASE!CreateFileW`) that breaks manual export table walking in reflective loaders. Solution: resolve only `GetProcAddress` manually, use it for everything else.
3. **CET-ready shellcode** — `endbr64` at all indirect call targets. Note: Windows currently enforces Shadow Stack + CFG, not IBT. This is forward-looking preparation, not a bypass of an active mitigation.

> **Honesty note:** The core techniques (section mapping, reflective loading, NtCreateThreadEx) are individually well-known. Siren's value is in the integration, documentation, and the forwarder fix — not in claiming a "new" injection method.

---

## Technique

```
INJECTOR                                   TARGET (child process)
────────                                   ──────────────────────
1. CreateProcess(SUSPENDED)         ──→    Created, only ntdll.dll loaded

2. NtCreateSection(RWX, pagefile)
   NtMapViewOfSection(self, RW)
   Write [PIC stub | payload PE]
   NtUnmapViewOfSection(self)
   NtMapViewOfSection(target, RWX)  ──→    Shared section mapped

3. ResumeThread()                   ──→    Process initializes (kernel32 loaded)

4. NtCreateThreadEx(SirenStubEntry) ──→    PIC stub executes:
   Close handles, EXIT                      • PEB walk → find kernel32.dll
                                             • Manual export walk → GetProcAddress
                                             • Reflective PE loading
                                             • Call DllMain(DLL_PROCESS_ATTACH)
```

---

## Comparison

| Feature | Classic Injection | Reflective DLL Injection | **Siren** |
|---|---|---|---|
| WriteProcessMemory | ✅ Required | ✅ Required | ❌ Not used |
| VirtualAllocEx | ✅ Required | ✅ Required | ❌ Not used |
| LoadLibrary | ✅ Required | ❌ Not used | ❌ Not used |
| Admin required | Sometimes | Usually | **Never** |
| API forwarders | ✅ Handled (OS) | ❌ Often broken | **✅ Handled** |
| Fire-and-forget | ❌ No | ❌ No | **✅ Yes** |

---

## Build

### Requirements

- CMake 3.20+
- MinGW-w64 cross-compiler (GCC with GAS assembler)
- Python 3 (for stub encryption at configure time)
- Linux host (cross-compilation to Windows x64)

### Compile

```bash
cd Siren
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/mingw64.cmake
cmake --build .
```

At configure time, `cmake/gen_stub.py` reads `cmake/stub_x64.bin`, encrypts it with
a fresh random 16-byte XOR key, and writes `sr_stub_gen.h` into the build directory —
every build produces a unique encrypted blob.

Output:
- `siren_injector.exe` — standalone injector

---

## Usage

On Windows (no admin required):

```powershell
.\siren_injector.exe .\payload.dll
```

The injector spawns `cmd.exe` as a suspended child, maps the payload into it via a
shared NT section (no `WriteProcessMemory`), then starts the PIC stub via
`NtCreateThreadEx`. The injector exits immediately; the payload runs independently.

---

## Project Structure

```
Siren/
├── src/
│   ├── siren.c                  # Injector + full injection pipeline
│   ├── siren.h                  # Public API (siren_inject)
│   ├── siren_stub_x64.S         # PIC reflective loader (x64 GAS assembly, 539 lines)
│   ├── siren_injector.manifest  # Windows manifest (UAC, DPI)
│   └── siren_injector.rc        # Windows resource file (version info)
├── cmake/
│   ├── gen_stub.py              # Encrypts stub binary → sr_stub_gen.h (run at configure)
│   ├── stub_x64.bin             # Pre-assembled PIC stub blob
│   ├── options.cmake            # Build flags and options
│   ├── version.cmake            # Version constants
│   ├── modules/                 # CMake utility modules (DetectArch, HardenFlags)
│   └── toolchains/              # Cross-compile toolchain files
├── doc/
│   ├── TECHNIQUE.md             # Technical deep-dive (EN)
│   └── TECHNIQUE.pt-BR.md      # Technical deep-dive (PT-BR)
├── CMakeLists.txt
├── README.md                    # This file (EN)
└── README.pt-BR.md             # Portuguese version
```

---

## License

MIT — see [LICENSE](LICENSE).

## Author

**Rafael Dornelas** — [rafaelwdornelasstl@gmail.com](mailto:rafaelwdornelasstl@gmail.com)
