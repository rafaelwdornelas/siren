# Siren — Phantom Section Loader: Technical Deep Dive

**Author:** Rafael Dornelas  
**Technique:** NtCreateSection + NtMapViewOfSection + NtCreateThreadEx  
**Target OS:** Windows 10/11 x64 (including 24H2 with CET-IBT)

---

## Table of Contents

1. [Prior Art & Contribution](#prior-art--contribution)
2. [Problem Statement](#problem-statement)
3. [Solution Overview](#solution-overview)
4. [CET-IBT: Forward-Looking Preparation](#cet-ibt-forward-looking-preparation)
5. [Injection Pipeline](#injection-pipeline)
6. [Memory Layout](#memory-layout)
7. [PIC Stub Architecture](#pic-stub-architecture)
8. [Section Mapping vs WriteProcessMemory](#section-mapping-vs-writeprocessmemory)
9. [GetProcAddress vs Manual Export Walking](#getprocaddress-vs-manual-export-walking)
10. [Design Decisions](#design-decisions)
11. [Comparison with Existing Techniques](#comparison-with-existing-techniques)

---

## Prior Art & Contribution

Siren builds on well-established techniques. Proper credit:

| Component | Prior Art |
|---|---|
| Section mapping without WPM | [Barakat, 2018](https://gist.github.com/Barakat/1dccd8e5336c660b18eeda46b86113ce); [SafeBreach / Pinjectra, Black Hat 2019](https://github.com/SafeBreach-Labs/pinjectra) |
| Reflective DLL injection | [Stephen Fewer, 2008](https://github.com/stephenfewer/ReflectiveDLLInjection) |
| Section delivery + manual PE loading | [Hunt & Hackett, 2022](https://www.huntandhackett.com/blog/concealed-code-execution-techniques-and-detection) |
| PEB walk + NtCreateThreadEx | Documented extensively since ~2017 |

**What Siren contributes:**

1. **Open-source reference implementation** — Clean C library integrating section injection + reflective PE loader with a simple `siren_inject()` API.
2. **API forwarder fix** — Documents the forwarder problem (e.g., `kernel32!CreateFileW → KERNELBASE!CreateFileW`) and solves it by resolving only `GetProcAddress` manually, then using it for all other imports.
3. **CET-ready shellcode** — `endbr64` at all indirect call targets. Note: Windows currently enforces Shadow Stack + CFG, not IBT. This is forward-looking preparation.

---

## Problem Statement

Existing DLL injection techniques fail on modern Windows 11 systems for three reasons:

### 1. Intel CET (Control-flow Enforcement Technology)

Intel CET has two components: **Shadow Stack** (return address validation) and **Indirect Branch Tracking / IBT** (requires `endbr64` at indirect call targets). Windows currently enforces Shadow Stack + CFG (Control Flow Guard), but **does not yet enforce IBT** on user-mode processes.

However, Siren includes `endbr64` at all indirect call targets as forward-looking preparation. If Microsoft enables IBT enforcement in future Windows versions, Siren will work without modification.

### 2. CreateRemoteThread Mitigations

`CreateRemoteThread` passes through kernel32's `CreateRemoteThreadEx`, which applies process mitigation policies. On Windows 11, many processes have `ProcessMitigationPolicy` set to block remote thread creation at the API level, returning `ERROR_ACCESS_DENIED (5)`.

### 3. API Forwarder Resolution

Windows DLLs extensively use **API forwarders**. For example, `kernel32.CreateFileW` forwards to `KERNELBASE.CreateFileW`. Manual export table walking (used by all known reflective loaders) returns the forwarder string instead of the function address, resulting in NULL IAT entries and crashes on the first Win32 API call.

---

## Solution Overview

Siren solves all three problems with a technique called **Phantom Section Loader**:

| Problem | Solution |
|---|---|
| CET-IBT | `endbr64` at all indirect call targets; payload compiled with `-fcf-protection=branch` |
| CreateRemoteThread blocked | Use `NtCreateThreadEx` (ntdll-level, bypasses kernel32 mitigation checks) |
| API forwarders | Use kernel32's `GetProcAddress` for import resolution (handles forwarders automatically) |
| WriteProcessMemory detection | Deliver payload via `NtCreateSection` + `NtMapViewOfSection` (shared section) |
| Admin/UAC requirement | Target is a child process (full handle access without privileges) |

---

## CET-IBT: Forward-Looking Preparation

### What is CET?

> **Important note:** Windows currently enforces **Shadow Stack + CFG**, not IBT. The `endbr64` instructions in Siren are forward-looking preparation, not a bypass of an active mitigation.

Intel **Control-flow Enforcement Technology (CET)** has two components:

- **Shadow Stack (SS):** Hardware-backed return address validation. The CPU maintains a separate shadow stack that records return addresses. `ret` instructions verify the return address matches the shadow stack entry.

- **Indirect Branch Tracking (IBT):** Every indirect `call` or `jmp` must land on an `endbr64` instruction. If the target does not begin with `endbr64`, the CPU raises `#CP`.

### Impact on Injection (When IBT Is Enforced)

If/when Windows enables IBT enforcement, any shellcode injected via `NtCreateThreadEx`, APC, or thread hijacking would need `endbr64` at its entry point. Siren is already prepared for this scenario.

### Siren's Solution

```asm
SirenStubEntry:
    endbr64                    ; ← CET-IBT: first instruction at entry
    lea     r10, .Lstub_fired[rip]
    mov     eax, 1
    lock xchg dword ptr [r10], eax
    ...
```

The PIC stub places `endbr64` (`F3 0F 1E FA`) as the very first instruction at `SirenStubEntry`. The payload DLL is compiled with `-fcf-protection=branch`, which inserts `endbr64` at `DllMain` and all other function entry points.

---

## Injection Pipeline

### Step 1: Spawn Suspended Host Process

```c
CreateProcessW(NULL, L"cmd.exe /c ping -n 60 127.0.0.1 >nul",
               ..., CREATE_SUSPENDED | CREATE_NO_WINDOW, ...);
```

The injector spawns a child process in suspended state. As the parent, we have full handle access (`PROCESS_ALL_ACCESS`) without needing `SeDebugPrivilege` or admin elevation.

### Step 2: Create and Map Section

```c
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &size,
                PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

// Map locally (RW) to write content
NtMapViewOfSection(hSection, GetCurrentProcess(), &local_view, ...);
siren_stub_write_to(local_view, ...);  // Write [PIC stub | PE payload]
NtUnmapViewOfSection(GetCurrentProcess(), local_view);

// Map into target (RWX)
NtMapViewOfSection(hSection, hProcess, &target_base, ...);
NtClose(hSection);
```

A single pagefile-backed section is created with `SEC_COMMIT`. It's mapped into the injector's address space as RW to write the content, then unmapped and mapped into the target as RWX. The section handle is closed — the mapping persists as long as the target process exists.

**Key insight:** No `WriteProcessMemory` is ever called. The shared section IS the write channel.

### Step 3: Resume and Wait

```c
ResumeThread(pi.hThread);
Sleep(2000);  // Wait for kernel32.dll to be loaded
```

The suspended process resumes and goes through `LdrInitializeThunk`, which loads `ntdll.dll → kernel32.dll → kernelbase.dll`. After ~100ms, the PEB's `InMemoryOrderModuleList` is fully populated.

### Step 4: Execute via NtCreateThreadEx

```c
void *entry = (char *)target_base + siren_stub_entry_offset();
NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                 entry, NULL, 0, 0, 0, 0, NULL);
WaitForSingleObject(hThread, 10000);
```

`NtCreateThreadEx` creates a thread in the target that starts executing at `SirenStubEntry` in the mapped section. Unlike `CreateRemoteThread`, this is a direct ntdll syscall that bypasses kernel32-level mitigation checks.

### Step 5: Fire-and-Forget

The injector closes all handles and exits. The payload continues running inside the target process independently.

---

## Memory Layout

```
Target Process Virtual Address Space
────────────────────────────────────

    ┌─────────────────────────────────────┐
    │         Mapped Section (RWX)        │  ← NtMapViewOfSection
    │                                     │
    │  ┌──────────────────────────────┐   │
    │  │  PIC Stub (siren_stub_code)  │   │  offset 0x000
    │  │                              │   │
    │  │  SirenStubEntry:             │   │  ← NtCreateThreadEx start
    │  │    endbr64                   │   │
    │  │    [atomic fired flag]       │   │
    │  │    [PEB walk → kernel32]     │   │
    │  │    [export walk → GPA]       │   │
    │  │    [resolve APIs]            │   │
    │  │    [PE loading logic]        │   │
    │  │    [call DllMain]            │   │
    │  │    ret                       │   │
    │  │                              │   │
    │  │  .Lstub_fired:    .long 0    │   │  atomic guard
    │  │  .Lstub_payload_offset: ...  │   │  patched by carrier
    │  │  "GetProcAddress\0"          │   │  embedded strings
    │  │  "VirtualAlloc\0"            │   │
    │  │  "LoadLibraryA\0"            │   │
    │  │  "FlushInstructionCache\0"   │   │
    │  └──────────────────────────────┘   │
    │  [padding to 4 KB boundary]         │
    │  ┌──────────────────────────────┐   │
    │  │  Payload PE (raw bytes)      │   │  offset = blob_size (4KB-aligned)
    │  │                              │   │
    │  │  MZ header                   │   │
    │  │  PE headers                  │   │
    │  │  .text section               │   │
    │  │  .rdata section              │   │
    │  │  .data section               │   │
    │  │  ...                         │   │
    │  └──────────────────────────────┘   │
    └─────────────────────────────────────┘

    ┌─────────────────────────────────────┐
    │  VirtualAlloc'd Image (RWX)         │  ← allocated by stub at runtime
    │                                     │
    │  PE loaded at preferred base        │
    │  Sections copied                    │
    │  Relocations applied                │
    │  Imports resolved (GetProcAddress)   │
    │  DllMain called                     │
    └─────────────────────────────────────┘
```

---

## PIC Stub Architecture

The PIC (Position-Independent Code) stub is the core of Siren. It's a self-contained x64 shellcode blob that:

### 1. Finds kernel32.dll via PEB Walk

```asm
mov     rax, gs:[0x60]          ; PEB
mov     rax, [rax + 0x18]       ; PEB->Ldr
lea     rdi, [rax + 0x20]       ; &InMemoryOrderModuleList
mov     rax, [rdi]              ; 1st entry (exe)
mov     rax, [rax]              ; 2nd entry (ntdll)
mov     rax, [rax]              ; 3rd entry (kernel32)
mov     r12, [rax + 0x20]       ; DllBase
```

The `InMemoryOrderModuleList` in the PEB always has kernel32.dll as the 3rd entry on Windows 10/11 x64.

### 2. Resolves GetProcAddress (Manual Export Walk)

Only `GetProcAddress` is resolved manually by walking kernel32's export directory. This is a one-time cost — all subsequent API resolution goes through `GetProcAddress`.

### 3. Resolves Remaining APIs

```asm
; VirtualAlloc, FlushInstructionCache, LoadLibraryA
mov     rcx, r12                ; kernel32 base
lea     rdx, .Lstr_VirtualAlloc[rip]
call    rbx                     ; GetProcAddress
```

### 4. Reflective PE Loading

The stub performs a full manual PE load:
- **Headers:** Copy `SizeOfHeaders` bytes
- **Sections:** Copy each section to its `VirtualAddress`
- **Relocations:** Process `IMAGE_REL_BASED_DIR64` entries (add delta to QWORDs)
- **Imports:** Walk `IMAGE_IMPORT_DESCRIPTOR`, call `LoadLibraryA` + `GetProcAddress` for each function

### 5. Call DllMain

```asm
mov     eax, [r13 + 0x28]      ; AddressOfEntryPoint
lea     rax, [r14 + rax]       ; DllMain absolute address
mov     rcx, r14               ; hinstDLL
mov     edx, 1                 ; DLL_PROCESS_ATTACH
xor     r8, r8                 ; lpvReserved = NULL
call    rax                    ; CET-safe (DllMain has endbr64)
```

---

## Section Mapping vs WriteProcessMemory

| Aspect | WriteProcessMemory | Section Mapping |
|---|---|---|
| API call | `kernel32!WriteProcessMemory` | `ntdll!NtMapViewOfSection` |
| Detection surface | Hooked by EDR/AV, logged by ETW | Lower-level, fewer hooks |
| Memory source | Injector's heap → target's allocated memory | Shared pagefile section |
| Permissions needed | `PROCESS_VM_WRITE` + `PROCESS_VM_OPERATION` | `PROCESS_VM_OPERATION` only |
| Allocation | Requires separate `VirtualAllocEx` | Section mapping IS the allocation |
| Cleanup | Must explicitly free on failure | Section auto-freed when mapping is removed |

---

## GetProcAddress vs Manual Export Walking

Traditional reflective loaders walk the export table manually to resolve API functions. This breaks on **API forwarders**.

### The Forwarder Problem

```
kernel32.dll export table:
  CreateFileW → "api-ms-win-core-file-l1-1-0.CreateFileW"
                 (forwarder string, NOT a function address)
```

A manual export walker returns the forwarder string pointer instead of the actual function address. The reflective loader writes this string pointer into the IAT, and the first call to `CreateFileW` jumps to a string — instant crash.

### Siren's Solution

Siren resolves `GetProcAddress` once (manually, from kernel32's export table — `GetProcAddress` itself is NOT a forwarder), then uses it for everything else:

```asm
; For each imported function:
mov     rcx, r8                ; hModule (loaded DLL)
mov     rdx, [import_name]     ; function name
call    [rbp - 0x58]           ; GetProcAddress — handles forwarders!
mov     [r10], rax             ; write to IAT
```

`GetProcAddress` internally follows the forwarder chain and returns the real function address in the target DLL (e.g., `KERNELBASE.CreateFileW`).

---

## Design Decisions

### Why cmd.exe as the host process?

On Windows 11, `notepad.exe` is a UWP wrapper that spawns a child process and exits. The parent PID becomes invalid before `NtCreateThreadEx` can be called. `cmd.exe` is a classic Win32 process that stays alive reliably.

### Why Sleep(2000) instead of WaitForInputIdle?

`WaitForInputIdle` only works with GUI processes that have a message loop. Console apps like `cmd.exe` cause it to return immediately with `WAIT_FAILED`. A 2-second sleep is more than sufficient for the NT loader to initialize kernel32.dll (~100ms in practice).

### Why NtCreateThreadEx instead of CreateRemoteThread?

`CreateRemoteThread` routes through `kernel32!CreateRemoteThreadEx`, which checks process mitigation policies. Protected processes on Windows 11 block this at the API level. `NtCreateThreadEx` is the underlying ntdll syscall and bypasses these checks.

### Why an atomic fired flag?

The stub includes a `lock xchg` atomic guard to prevent double execution. In scenarios where multiple trigger mechanisms are armed (e.g., InstrumentationCallback + NtCreateThreadEx), the flag ensures the reflective loader runs exactly once.

---

## Comparison with Existing Techniques

| Technique | Delivery | Trigger | CET | Admin | Forwarders |
|---|---|---|---|---|---|
| CreateRemoteThread + LoadLibrary | WPM | CRT | N/A | Sometimes | ✅ (OS handles) |
| APC Injection | WPM | QueueUserAPC | ❌ | Sometimes | Depends |
| Thread Hijacking (SetThreadContext) | WPM | RIP redirect | ❌ | Yes | Depends |
| Reflective DLL Injection | WPM | CRT/APC | ❌ | Usually | ❌ Broken |
| Process Hollowing | WPM | SetThreadContext | ❌ | Sometimes | N/A |
| **Siren (Phantom Section Loader)** | **Section Map** | **NtCreateThreadEx** | **✅** | **No** | **✅** |

---

## References

- [Intel CET Specification](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html)
- [Windows Internals, 7th Edition](https://docs.microsoft.com/en-us/sysinternals/) — PEB structure, LDR data
- [ReactOS Source](https://reactos.org/) — NT API documentation
- [MSDN: NtCreateSection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatesection)
