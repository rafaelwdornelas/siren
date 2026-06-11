/*
 * src/slack/slack_finder.c
 *
 * Finds writable section slack space in a remote process PE image.
 *
 * Algorithm:
 *   1. Enumerate modules in target via CreateToolhelp32Snapshot to get the
 *      base address of the named module.
 *   2. NtReadVirtualMemory the PE headers (DOS + NT + sections).
 *   3. For each writable section: slack = SizeOfRawData - VirtualSize
 *      (rounded to 16-byte alignment).
 *   4. Return the first section with >= SIREN_STUB_MIN_SLACK bytes of slack.
 */

#include "slack/slack_finder.h"
#include "siren/siren_types.h"
#include "pe/pe_parse.h"

#include <tlhelp32.h>
#include <string.h>
#include <wchar.h>

/* Maximum header bytes to read from the remote process (4 KB is always safe
 * for a well-formed PE; headers are always mapped at the image base). */
#define HEADER_READ_SIZE 4096u

static int wcs_iequal_mod(const wchar_t *a, const wchar_t *b)
{
    while (*a && *b) {
        if (towlower((wint_t)*a) != towlower((wint_t)*b))
            return 0;
        ++a; ++b;
    }
    return *a == L'\0' && *b == L'\0';
}

/* Find module base in target process using Toolhelp32 snapshot. */
static BOOL find_module_base(HANDLE   hProcess,
                             const wchar_t *name,
                             uintptr_t     *out_base)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE |
                                           TH32CS_SNAPMODULE32,
                                           GetProcessId(hProcess));
    if (snap == INVALID_HANDLE_VALUE)
        return FALSE;

    MODULEENTRY32W me = { sizeof(me) };
    BOOL found = FALSE;

    if (Module32FirstW(snap, &me)) {
        do {
            if (wcs_iequal_mod(me.szModule, name)) {
                *out_base = (uintptr_t)me.modBaseAddr;
                found = TRUE;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

siren_status_t siren_slack_find(HANDLE         hProcess,
                                const wchar_t *module_name,
                                void         **out_addr,
                                size_t        *out_size)
{
    if (!hProcess || !module_name || !out_addr || !out_size)
        return SIREN_E_NULL_ARG;

    *out_addr = NULL;
    *out_size = 0;

    /* ── 1. Locate module base in target ─────────────────────────── */
    uintptr_t mod_base = 0;
    if (!find_module_base(hProcess, module_name, &mod_base))
        return SIREN_E_MODULE_NOT_FOUND;

    /* ── 2. Read PE headers from target ──────────────────────────── */
    uint8_t  hdr_buf[HEADER_READ_SIZE];
    SIZE_T   bytes_read = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)mod_base,
                           hdr_buf, sizeof(hdr_buf), &bytes_read) ||
        bytes_read < sizeof(sr_pe_dos_hdr))
        return SIREN_E_SLACK_READ;

    /* ── 3. Validate PE and iterate sections ─────────────────────── */
    sr_pe_view view;
    siren_status_t r = sr_pe_validate(hdr_buf, bytes_read, &view);
    if (SIREN_FAILED(r))
        return r;

    /* ── 4. Find first writable section with enough slack ─────────── */
    for (uint16_t i = 0; i < view.section_count; ++i) {
        const sr_pe_section_hdr *s = &view.sections[i];

        /* Must be writable and have both Virtual + Raw sizes. */
        if (!(s->Characteristics & SIREN_PE_SCN_MEM_WRITE))
            continue;
        if (s->VirtualSize == 0 || s->SizeOfRawData == 0)
            continue;
        /* Executable sections are fine as carrier but prefer non-exec. */

        /* Slack = bytes between end-of-used-content and end-of-raw-data. */
        uint32_t used = s->VirtualSize;
        if (used > s->SizeOfRawData)
            continue;  /* VirtualSize > RawData → no raw slack */

        /* Align used up to 16 to avoid splitting any data structure. */
        uint32_t used_aligned = sr_pe_align_up(used, 16u);
        if (used_aligned >= s->SizeOfRawData)
            continue;

        uint32_t slack = s->SizeOfRawData - used_aligned;
        if (slack < SIREN_STUB_MIN_SLACK)
            continue;

        /* Virtual address of the slack start inside the target process. */
        *out_addr = (void *)(mod_base + s->VirtualAddress + used_aligned);
        *out_size = (size_t)slack;
        return SIREN_OK;
    }

    return SIREN_E_SLACK_NOT_FOUND;
}
