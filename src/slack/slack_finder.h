/*
 * src/slack/slack_finder.h
 *
 * Locates usable slack space (zero-padding at the end of a writable PE
 * section) in a remote process without allocating new virtual memory.
 *
 * The slack space is used as the carrier for the stub + notify entry,
 * eliminating VirtualAllocEx from the injector's IOC profile.
 */

#ifndef SIREN_SLACK_FINDER_H
#define SIREN_SLACK_FINDER_H

#include "siren/siren_status.h"

#include <stddef.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * siren_slack_find
 *
 * Scan the PE sections of `module_name` (already loaded in hProcess) and
 * return the address and available byte count of the first writable section
 * that has >= SIREN_STUB_MIN_SLACK bytes of inter-alignment padding.
 *
 * Prefers sections named ".data" or ".rdata"; falls back to any writable
 * section with sufficient slack.
 *
 * out_addr  — virtual address of the slack region inside the target process
 * out_size  — number of usable slack bytes
 */
siren_status_t siren_slack_find(HANDLE         hProcess,
                                const wchar_t *module_name,
                                void         **out_addr,
                                size_t        *out_size);

#ifdef __cplusplus
}
#endif

#endif /* SIREN_SLACK_FINDER_H */
