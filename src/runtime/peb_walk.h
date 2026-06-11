/*
 * src/runtime/peb_walk.h
 *
 * Walks PEB.Ldr.InMemoryOrderModuleList to locate a loaded module.
 * Adapted from Wraith — no GetModuleHandle, no loader-lock entry.
 */

#ifndef SIREN_PEB_WALK_H
#define SIREN_PEB_WALK_H

#include "siren/siren_status.h"

#include <stdint.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Find the base address of a module by its wide (Unicode) name.
 * Comparison is case-insensitive.  Only the base name is compared
 * (e.g. L"kernel32.dll"), not the full path.
 *
 * Returns SIREN_OK + *out_base on success.
 * Returns SIREN_E_MODULE_NOT_FOUND if the module is not in the PEB.
 */
siren_status_t sr_pebwalk_find_w(const wchar_t *name, void **out_base);

/*
 * ASCII convenience wrapper — converts name to lowercase before comparing.
 */
siren_status_t sr_pebwalk_find_a(const char *name, void **out_base);

/*
 * Return the base address of ntdll.dll (always present, fast path).
 */
void *sr_pebwalk_ntdll_base(void);

#ifdef __cplusplus
}
#endif

#endif /* SIREN_PEB_WALK_H */
