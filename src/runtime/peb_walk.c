/*
 * src/runtime/peb_walk.c
 *
 * PEB walker — locates loaded modules without calling GetModuleHandle.
 * Adapted from Wraith (prefix wr_ → sr_).
 *
 * Walks PEB.Ldr.InMemoryOrderModuleList.  The InMemoryOrder list is
 * preferred over InLoadOrder because its head-pointer offset within
 * LDR_DATA_TABLE_ENTRY has been stable across every Windows version
 * from NT 3.51 through Windows 11 24H2.
 */

#include "runtime/peb_walk.h"

#include <winternl.h>
#include <wchar.h>
#include <ctype.h>

/* Minimal LDR_DATA_TABLE_ENTRY layout — only fields we access.
 * Stable offsets for x64: Win10 1809 .. Win11 24H2. */
typedef struct sr_ldr_entry {
    LIST_ENTRY     InLoadOrderLinks;          /* +0x00 */
    LIST_ENTRY     InMemoryOrderLinks;        /* +0x10 */
    LIST_ENTRY     InInitializationOrderLinks; /* +0x20 */
    PVOID          DllBase;                   /* +0x30 */
    PVOID          EntryPoint;                /* +0x38 */
    ULONG          SizeOfImage;               /* +0x40 */
    UNICODE_STRING FullDllName;               /* +0x48 */
    UNICODE_STRING BaseDllName;               /* +0x58 */
} sr_ldr_entry;

#define SR_ENTRY_FROM_INMEMORY(p) \
    ((sr_ldr_entry *)((uint8_t *)(p) - offsetof(sr_ldr_entry, InMemoryOrderLinks)))

/* Case-insensitive wide-string comparison (no locale dependency). */
static int wcs_iequal(const wchar_t *a, size_t a_len,
                      const wchar_t *b, size_t b_len)
{
    if (a_len != b_len)
        return 0;
    for (size_t i = 0; i < a_len; ++i) {
        wchar_t ca = (wchar_t)towlower((wint_t)a[i]);
        wchar_t cb = (wchar_t)towlower((wint_t)b[i]);
        if (ca != cb)
            return 0;
    }
    return 1;
}

siren_status_t sr_pebwalk_find_w(const wchar_t *name, void **out_base)
{
    if (!name || !out_base)
        return SIREN_E_NULL_ARG;
    *out_base = NULL;

    size_t name_len = wcslen(name);

    PPEB peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    if (!peb || !peb->Ldr)
        return SIREN_E_MODULE_NOT_FOUND;

    PLIST_ENTRY head = &((PPEB_LDR_DATA)peb->Ldr)->InMemoryOrderModuleList;
    PLIST_ENTRY cur  = head->Flink;

    while (cur && cur != head) {
        sr_ldr_entry *e = SR_ENTRY_FROM_INMEMORY(cur);

        if (e->BaseDllName.Buffer && e->BaseDllName.Length > 0) {
            size_t entry_len = e->BaseDllName.Length / sizeof(wchar_t);
            if (wcs_iequal(name, name_len,
                           e->BaseDllName.Buffer, entry_len)) {
                /* Reject placeholder / partially-initialised entries. */
                if ((uintptr_t)e->DllBase >= 0x10000u) {
                    *out_base = e->DllBase;
                    return SIREN_OK;
                }
            }
        }
        cur = cur->Flink;
    }
    return SIREN_E_MODULE_NOT_FOUND;
}

siren_status_t sr_pebwalk_find_a(const char *name, void **out_base)
{
    if (!name)
        return SIREN_E_NULL_ARG;

    /* Convert ASCII to wide on the stack (module names are short). */
    wchar_t wname[256];
    int i = 0;
    while (name[i] && i < 255) {
        wname[i] = (wchar_t)(unsigned char)name[i];
        ++i;
    }
    wname[i] = L'\0';
    return sr_pebwalk_find_w(wname, out_base);
}

void *sr_pebwalk_ntdll_base(void)
{
    void *base = NULL;
    sr_pebwalk_find_w(L"ntdll.dll", &base);
    return base;
}
