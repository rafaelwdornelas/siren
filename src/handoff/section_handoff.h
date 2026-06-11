/*
 * src/handoff/section_handoff.h
 *
 * Creates a pagefile-backed section containing the PE payload and
 * transplants the section handle into the target process via
 * DuplicateHandle.  After this call the injector may close all its
 * own handles and exit — the section lives as long as the target
 * holds its duplicated handle.
 */

#ifndef SIREN_SECTION_HANDOFF_H
#define SIREN_SECTION_HANDOFF_H

#include "siren/siren_status.h"

#include <stddef.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * siren_section_create_and_handoff
 *
 * 1. NtCreateSection(SEC_COMMIT, PAGE_EXECUTE_READ) backed by pagefile.
 * 2. NtMapViewOfSection into the injector's address space (RW).
 * 3. memcpy the PE bytes.
 * 4. NtUnmapViewOfSection.
 * 5. DuplicateHandle into hProcess.
 * 6. NtClose the local handle.
 *
 * On success *out_target_handle holds the handle value as it exists
 * inside hProcess (not a valid handle in the calling process).
 */
siren_status_t siren_section_create_and_handoff(HANDLE      hProcess,
                                                const void *pe_bytes,
                                                size_t      pe_size,
                                                HANDLE     *out_target_handle);

#ifdef __cplusplus
}
#endif

#endif /* SIREN_SECTION_HANDOFF_H */
