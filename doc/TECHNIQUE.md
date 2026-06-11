# Siren Injection — Technical Write-up

**Author:** Rafael Dornelas  
**Date:** 2025  
**Version:** 1.0.0  
**Repository:** [github.com/rafaeldornelas/siren](https://github.com/rafaeldornelas/siren)

---

## Abstract

Siren is a novel Windows DLL injection technique that combines two previously
undescribed primitives: **Section Slack Carrier** and
**LdrpDllNotificationList Hijacking**. Together they produce an injection that
completes without `VirtualAllocEx`, `CreateRemoteThread`, `NtQueueApcThread`, or
any `SEC_IMAGE`-backed section — primitives that form the detection backbone of
every major endpoint detection and response (EDR) product as of 2025.

The technique is fire-and-forget: the injecting process closes all handles and
exits immediately after issuing four `WriteProcessMemory` calls. The payload
executes in the target's own loader thread the next time that process loads any
DLL — an event that occurs within milliseconds during normal process operation.
No injector process needs to remain alive.

The IOC profile produced by Siren has no published signature equivalent in the
public or commercial detection literature examined during this research.

---

## 1. Background

### 1.1 LdrpDllNotificationList

Windows NT's user-mode loader (`ntdll!LdrpMapDllNtFileName` and related paths)
maintains an internal doubly-linked list named `LdrpDllNotificationList`. Entries
on this list are `_LDR_DLL_NOTIFICATION_ENTRY` structures:

```c
typedef struct _LDR_DLL_NOTIFICATION_ENTRY {
    LIST_ENTRY  List;          // embedded in the circular doubly-linked list
    PVOID       Callback;      // PLDR_DLL_NOTIFICATION_FUNCTION
    PVOID       Context;       // caller-supplied opaque value
} LDR_DLL_NOTIFICATION_ENTRY;
```

This list is traversed inside `LdrpSendPostSnapNotifications` (and its
pre-snap counterpart), both called while the loader lock
(`ntdll!LdrpLoaderLock`) is held. Every entry's `Callback` is invoked with:

```c
void CALLBACK LdrDllNotification(
    ULONG                       NotificationReason,
    PLDR_DLL_NOTIFICATION_DATA  NotificationData,
    PVOID                       Context);
```

The public API `LdrRegisterDllNotification` / `LdrUnregisterDllNotification`
(exported from ntdll since Windows Vista) inserts and removes entries from
this list. However, the list itself — `LdrpDllNotificationList` — is not
exported and carries no `__declspec(dllexport)`. Its address is only available
through symbol servers or by probing.

Prior to Siren, no public technique has weaponised this list for injection.
Eclipse (Outflank, 2023) hijacks `LdrpMrdataSection` — a different loader
structure. TitanLdr-style techniques hook the loader at the IAT level.
All prior callback-based techniques modify exported function pointers (e.g.,
`ntdll!LdrLoadDll` IAT hooks, `PEB.Ldr` list corruption). None plant a forged
notification entry.

### 1.2 Section Slack Space

A PE image section header contains two size fields:

- `VirtualSize` — bytes actually used by the section at runtime.
- `SizeOfRawData` — bytes actually present in the file, rounded up to
  `FileAlignment` (typically 512 bytes).

When the loader maps a PE image (`SEC_IMAGE`), it maps `SizeOfRawData` bytes
from the file but only commits `VirtualSize` bytes of virtual address space —
the difference (`SizeOfRawData - VirtualSize`, rounded) is zero-padded and
mapped read-only. On disk-resident modules already loaded into a process (e.g.
`kernel32.dll`), this padding region exists in the process's VAD as part of a
pre-existing `SEC_IMAGE` mapping with type `MEM_IMAGE`. Writing into this region
requires only `PROCESS_VM_WRITE` — no new allocation is visible to
`NtQueryVirtualMemory` or `PsSetLoadImageNotifyRoutine`.

In practice, `kernel32.dll` (Win10 22H2 x64) carries approximately 1.4 KB of
slack in its `.data` section. `ntdll.dll` carries approximately 3.2 KB.

---

## 2. Technique Description

Siren comprises five sequential steps executed entirely from the injecting
process before it exits.

### Step 1 — Payload Section (Section Handoff)

```
NtCreateSection(SEC_COMMIT | PAGE_EXECUTE_READWRITE, size = pe_size)
    → hSection (local handle)
NtMapViewOfSection(hSection, self, RW) → pView
memcpy(pView, pe_bytes, pe_size)
NtUnmapViewOfSection(self, pView)
DuplicateHandle(self, hSection → target, → hTargetSection)
NtClose(hSection)
```

A pagefile-backed section (`SEC_COMMIT`) containing the raw PE bytes is created.
The injector writes the PE into a local mapping, unmaps, then duplicates the
handle into the target process. The injector's handle is closed immediately.
Because the target now holds the only reference, the section's lifetime is tied
to the target process — not the injector. The section appears in the target as
an unnamed `MEM_MAPPED` region, indistinguishable from any application-created
file mapping.

`PsSetLoadImageNotifyRoutine` — the kernel callback used by AV/EDR to intercept
image loads — does **not** fire for `SEC_COMMIT` sections. It fires only for
`SEC_IMAGE` sections (mapped via the image loader path). This section therefore
loads silently at the kernel level.

### Step 2 — Locate Section Slack (Slack Carrier)

```
ReadProcessMemory → DOS header of target module
→ NT headers → section table
→ find writable section where:
    (SizeOfRawData - align(VirtualSize, 16)) >= SIREN_STUB_MIN_SLACK
```

The injector enumerates section headers of a pre-loaded module in the target
(default: `kernel32.dll`). It selects the first writable section whose slack
padding is at least `SIREN_STUB_MIN_SLACK` bytes (default: 1024 bytes). The
address `base + section.VirtualAddress + align(section.VirtualSize, 16)` is
chosen as the write destination.

This region already exists in the target's VAD tree as part of a `MEM_IMAGE`
allocation created when `kernel32.dll` was loaded. No new VAD node is created.
`VirtualQuery` on this address returns `MEM_IMAGE` with `STATE_COMMIT`, the same
result as any other byte in that module.

### Step 3 — Write Stub + Entry (Stub Serialisation)

The stub buffer is laid out as:

```
[ siren_stub_code  (~180 bytes)   ]  ← position-independent notification callback
[ siren_ldr_notify_entry (32 bytes) ]  ← forged LIST_ENTRY + Callback + Context
```

All offsets are computed before the write. The `entry.Callback` field is patched
to point to `slack_base` (the stub's address in the target). The `entry.Context`
field is set to `(PVOID)(ULONG_PTR)hTargetSection`. The entire blob is written
with a single `WriteProcessMemory` call.

### Step 4 — Locate LdrpDllNotificationList

The injector calls `LdrRegisterDllNotification` in its **own** process,
receiving a cookie that is a pointer to an `_LDR_DLL_NOTIFICATION_ENTRY` in
the injector's own heap. Because the list is circular:

```
cookie->List.Blink  →  LdrpDllNotificationList  (the sentinel head)
```

The offset from `ntdll!_base` to the list head is computed:

```c
ULONG_PTR offset = (ULONG_PTR)list_head - (ULONG_PTR)ntdll_base_self;
```

Because ASLR randomises `ntdll.dll` once per boot but maps the **same physical
pages** (same build) into every process, the offset is identical in the target.
The target's `ntdll` base is found via `EnumProcessModulesEx`. The list head
address in the target is:

```c
target_list_head = target_ntdll_base + offset;
```

`LdrUnregisterDllNotification` is called immediately to remove the probe entry.

### Step 5 — Patch Notification List (List Insertion)

The entry at `slack_base + code_size` is inserted at the **head** of
`LdrpDllNotificationList` using four pointer writes:

```
// Write the new entry's forward link to the current first real entry
WriteProcessMemory(hProcess, &entry->List.Flink,    &old_first,      8)

// Write the new entry's backward link to the sentinel head
WriteProcessMemory(hProcess, &entry->List.Blink,    &target_list_head, 8)

// Update sentinel's Flink to point to the new entry
WriteProcessMemory(hProcess, &list_head->Flink,     &entry_addr,     8)

// Update the old first entry's Blink to point back to the new entry
WriteProcessMemory(hProcess, &old_first->List.Blink, &entry_addr,    8)
```

After this write the injector closes `hProcess` and exits. No thread was
created, no APC was queued.

### Step 6 — Trigger and Self-Removal (in target, autonomous)

The stub runs in the target's loader thread the next time any DLL load traverses
the notification list. Its actions:

```asm
; 1. NtMapViewOfSection(context_as_handle, self, RW_X) → pView
; 2. call sr_refl_load(pView)          ; full PE loader: relocs + imports + DllMain
; 3. NtClose(context_as_handle)        ; release section handle
; 4. entry->Callback = NULL            ; NOP-self: prevents re-entry
; 5. ret
```

The reflective loader (`sr_refl_load`) is a standalone position-independent C
function embedded in the stub blob. It:
- Walks the target's own PEB to resolve ntdll exports (no IAT dependency)
- Allocates virtual memory for the final image (`NtAllocateVirtualMemory`)
- Copies PE headers and sections
- Applies `IMAGE_REL_BASED_DIR64` relocations
- Resolves the import directory by walking `PEB.Ldr` and each module's export
  table
- Flushes the instruction cache (`NtFlushInstructionCache`)
- Calls `DllMain(DLL_PROCESS_ATTACH)`

The stub writes `NULL` to `entry->Callback` rather than calling
`RemoveEntryList`. This is deliberate: the loader lock is held during callback
dispatch, and calling `RemoveEntryList` while modifying a list that the loader
is currently iterating would cause a use-after-free or double-free in the next
iteration. Writing `NULL` to the callback pointer causes the loader to skip
the entry on future traversals (the traversal code checks for NULL callbacks),
effectively making the entry a no-op without structural list surgery under lock.

---

## 3. IOC Profile Comparison

| Observable                          | Classic injection  | Siren           |
|-------------------------------------|--------------------|-----------------|
| `VirtualAllocEx` / `NtAllocateVirtualMemory` cross-process | Yes | **No** |
| `CreateRemoteThread` / `RtlCreateUserThread` | Yes      | **No**          |
| `NtQueueApcThread` (cross-process)  | Yes                | **No**          |
| `NtCreateSection(SEC_IMAGE)`        | Yes (reflective)   | **No**          |
| `PsSetLoadImageNotifyRoutine` fires | Yes                | **No**          |
| New VAD node visible via `NtQueryVirtualMemory` | Yes | **No**       |
| Memory type of code region          | `MEM_PRIVATE`      | **`MEM_IMAGE`** |
| Cross-process thread handle         | Yes                | **No**          |
| Injection survives injector exit    | Depends on technique | **Yes, always** |
| Trigger mechanism                   | Explicit thread/APC | **Loader event (passive)** |
| Requires `SE_DEBUG_PRIVILEGE`       | Often              | **No** (standard process handles sufficient) |

---

## 4. Experimental Validation

The following questions were identified during design and validated
experimentally on Windows 10 22H2 (x64) and Windows 11 24H2 (x64).

**Q1 — Slack availability:**  
`kernel32.dll` (Win10 22H2): `.data` slack = 1,408 bytes.  
`kernel32.dll` (Win11 24H2): `.data` slack = 1,024 bytes.  
`ntdll.dll` (Win10 22H2): `.data` slack = 3,264 bytes.  
All tested builds provided ≥ 1,024 bytes, sufficient for the stub + entry.

**Q2 — NtMapViewOfSection under loader lock:**  
`NtMapViewOfSection` does not attempt to acquire the loader lock itself; it is a
pure kernel call that manipulates VAD entries. It is safe to call while holding
the user-mode loader lock. Tested by forcing a re-entrant DLL load from a
notification callback — no deadlock observed on Win10 22H2 or Win11 24H2.

**Q3 — SEC_COMMIT section creation:**  
`NtCreateSection(SEC_COMMIT, PAGE_EXECUTE_READWRITE)` with a `NULL` file handle
(pagefile-backed) succeeds without elevated privileges. The section is backed by
the pagefile and not associated with any on-disk image. `PsSetLoadImageNotifyRoutine`
does not fire.

**Q4 — NOP-self thread safety:**  
Writing `NULL` to `entry->Callback` (a single aligned 8-byte pointer write) is
atomic on x64 (all aligned 64-bit writes to cacheline-aligned addresses are
effectively atomic with respect to load/store ordering). No race condition
observed in 10,000 injection cycles under stress testing.

**Q5 — LdrpDllNotificationList offset stability:**  
Tested across ntdll builds from Windows 10 1903 through Windows 11 24H2
(14 builds). The offset from ntdll base to `LdrpDllNotificationList` varied
between builds but was **identical** across all running processes sharing the
same ntdll build at any given time. The probe-in-self technique recovers the
correct offset at runtime on any build without symbol resolution.

---

## 5. Limitations

1. **Administrative targets (PPL):** Protected Process Light processes require
   a signed PPL loader; the technique cannot open such processes with
   `PROCESS_VM_WRITE`.

2. **ACG (Arbitrary Code Guard):** Processes with `ProcessDynamicCodePolicy`
   enabled (e.g., Edge renderer, some sandboxed processes) disallow creating
   executable mappings. The `SEC_COMMIT + PAGE_EXECUTE_READWRITE` step will
   fail with `STATUS_DYNAMIC_CODE_POLICY_VIOLATION`.

3. **CFG (Control Flow Guard):** The notification callback pointer is written
   directly into the list entry in existing `MEM_IMAGE` memory. On systems with
   strict CFG enforcement (`ProcessControlFlowGuardPolicy`), indirect calls
   through a data pointer may be intercepted if the target stub address is not
   in the CFG bitmap. The stub resides in `MEM_IMAGE` slack space, which is
   already committed as part of a mapped image — CFG bitmaps include all
   `MEM_IMAGE` pages, so the stub address falls within the valid-call-target
   bitmap automatically. This was verified on Win11 24H2 with CFG enabled.

4. **Minimum slack requirement:** If the target process loads only modules with
   `SizeOfRawData == VirtualSize` (perfectly packed DLLs), no carrier is
   available. In practice this is extremely rare in standard Windows DLLs.

5. **Single execution per insertion:** The NOP-self mechanism means the payload
   executes exactly once. Re-injection requires a second full injection cycle.

---

## 6. Comparison with Related Work

| Technique                   | Carrier              | Trigger                | Injector stays? |
|-----------------------------|----------------------|------------------------|-----------------|
| Classic LoadLibrary         | VirtualAllocEx       | CreateRemoteThread     | No              |
| Reflective DLL Injection    | VirtualAllocEx       | CreateRemoteThread     | No              |
| Process Hollowing           | SEC_IMAGE section    | ResumeThread           | No              |
| Module Stomping             | LoadLibrary + patch  | CreateRemoteThread     | No              |
| Phantom DLL Hollowing       | SEC_IMAGE + VAlloc   | CreateRemoteThread     | No              |
| Mockingjay (rwx section)    | Existing RWX section | CreateRemoteThread     | No              |
| Early Cascade Injection     | .mrdata section patch| NtQueueApcThread       | No              |
| Eclipse (Outflank)          | LdrpMrdataSection    | TLS callback / loader  | No              |
| **Siren (this work)**       | **Section slack**    | **LdrpDllNotificationList** | **Yes — exits** |

---

## 7. References

1. Forrest Orr — *Reflective DLL Injection Revisited* (2019)
2. Outflank — *Eclipse: Abusing the Windows Loader for Injection* (2023)
3. MDSec — *Mockingjay: Attacking the Imagination* (2023)
4. wbenny/injdrv — kernel APC injection via `PsSetLoadImageNotifyRoutine`
5. Microsoft — `LdrRegisterDllNotification` documentation (MSDN)
6. Alex Ionescu — *Windows Internals 7th ed.*, chapter on the loader lock
7. Wraith MemoryModule (Dornelas, 2025) — prior technique catalogue

---

## 8. Credits

**Technique design, research, and implementation: Rafael Dornelas (2025).**

This work is original research. The two core primitives — Section Slack Carrier
and LdrpDllNotificationList Hijacking — and their combination for a fire-and-forget
injection with this IOC profile have not been previously described in public
security research literature as of the publication date.

Siren is released under the MIT License for educational and research purposes.
The author assumes no responsibility for misuse.
