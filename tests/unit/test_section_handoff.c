/*
 * tests/unit/test_section_handoff.c
 *
 * Q3: Does NtCreateSection(SEC_COMMIT, PAGE_EXECUTE_READ) work for
 *     pagefile-backed sections containing PE content?
 *
 * Creates a small PE-like buffer, hands it off to the current process,
 * maps it back and verifies the content survived.
 */

#include "siren/siren.h"
#include "handoff/section_handoff.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

/* Minimal placeholder bytes (not a valid PE, just content integrity check) */
static const uint8_t TEST_CONTENT[256] = {
    'M', 'Z', 0x90, 0x00,  /* fake DOS magic */
    0x53, 0x49, 0x52, 0x45, 0x4E,  /* "SIREN" */
};

int main(void)
{
    HANDLE hSelf = OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_VM_READ,
        FALSE, GetCurrentProcessId());

    if (!hSelf) {
        fprintf(stderr, "FAIL: OpenProcess self: %lu\n", GetLastError());
        return 1;
    }

    /* ── Create section and hand handle to self ─────────────── */
    HANDLE hTarget = NULL;
    siren_status_t r = siren_section_create_and_handoff(
        hSelf, TEST_CONTENT, sizeof(TEST_CONTENT), &hTarget);

    CloseHandle(hSelf);

    if (SIREN_FAILED(r)) {
        fprintf(stderr, "FAIL: siren_section_create_and_handoff: %s\n",
                siren_status_string(r));
        return 1;
    }
    printf("PASS: section created, handle in self = %p\n", (void *)hTarget);

    /* ── Map the section back and verify content ────────────── */
    /* NtMapViewOfSection via the duplicated handle */
    typedef LONG (NTAPI *PFN_NtMapViewOfSection)(
        HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
        PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NtMapViewOfSection NtMVOS = (PFN_NtMapViewOfSection)
        GetProcAddress(ntdll, "NtMapViewOfSection");

    if (!NtMVOS) {
        fprintf(stderr, "FAIL: NtMapViewOfSection not found\n");
        return 1;
    }

    PVOID  base    = NULL;
    SIZE_T view_sz = 0;
    LONG   st = NtMVOS(hTarget, (HANDLE)-1, &base,
                       0, 0, NULL, &view_sz, 2 /* ViewUnmap */,
                       0, PAGE_READONLY);

    if (st < 0 || !base) {
        fprintf(stderr, "FAIL: NtMapViewOfSection: 0x%08lX\n", (unsigned long)st);
        return 1;
    }

    /* Verify first bytes */
    if (memcmp(base, TEST_CONTENT, sizeof(TEST_CONTENT)) != 0) {
        fprintf(stderr, "FAIL: content mismatch after round-trip\n");
        return 1;
    }
    printf("PASS: content verified after DuplicateHandle + NtMapViewOfSection\n");

    /* Cleanup */
    typedef LONG (NTAPI *PFN_NtUMVOS)(HANDLE, PVOID);
    PFN_NtUMVOS NtUMVOS = (PFN_NtUMVOS)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    if (NtUMVOS) NtUMVOS((HANDLE)-1, base);
    CloseHandle(hTarget);

    printf("PASS: section handoff test complete\n");
    return 0;
}
