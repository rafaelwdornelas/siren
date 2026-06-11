#ifndef SIREN_H
#define SIREN_H

/*
 * Siren Injection — public API
 *
 * Technique: LdrpDllNotificationList Hijacking + Section Slack Carrier
 * Author:    Rafael Dornelas  <rafaelwdornelasstl@gmail.com>
 * License:   MIT
 *
 * After siren_inject() returns SIREN_OK the caller may close all handles
 * and exit.  The payload DLL will be loaded into the target process the next
 * time the Windows loader delivers any DLL-load notification — which happens
 * automatically as part of normal process activity.
 */

#include "siren_status.h"
#include "siren_types.h"

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * siren_inject
 *
 * Inject pe_bytes (a valid x64 PE DLL image) into the process identified by
 * hProcess.  opts may be NULL for defaults.
 *
 * On success: returns SIREN_OK.  The caller DOES NOT need to keep hProcess or
 * any other handle open — the payload is self-sustaining inside the target.
 *
 * hProcess must have been opened with at least:
 *   PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE
 */
siren_status_t siren_inject(HANDLE                       hProcess,
                            const void                  *pe_bytes,
                            size_t                       pe_size,
                            const siren_inject_options  *opts);

/*
 * siren_status_string
 *
 * Returns a static ASCII string describing the status code.
 */
const char *siren_status_string(siren_status_t s);

#ifdef __cplusplus
}
#endif

#endif /* SIREN_H */
