/*
 * siren.h — Phantom Section Loader
 * Author: Rafael Dornelas
 * License: MIT
 */
#ifndef SIREN_H
#define SIREN_H

#include <stddef.h>
#include <stdint.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Status codes ─────────────────────────────────────────────────── */

typedef int32_t siren_status_t;

#define SIREN_OK                 ((siren_status_t)0)
#define SIREN_MAKE_STATUS(c, s)  (((siren_status_t)(c) << 24) | (siren_status_t)(s))
#define SIREN_SUCCESS(s)         ((s) == 0)
#define SIREN_FAILED(s)          ((s) != 0)

#define SIREN_E_NULL_ARG         SIREN_MAKE_STATUS(0x01, 0x01)
#define SIREN_E_BAD_SIZE         SIREN_MAKE_STATUS(0x01, 0x02)
#define SIREN_E_PE_BAD_DOS       SIREN_MAKE_STATUS(0x02, 0x01)
#define SIREN_E_PE_BAD_NT        SIREN_MAKE_STATUS(0x02, 0x02)
#define SIREN_E_PE_WRONG_ARCH    SIREN_MAKE_STATUS(0x02, 0x03)
#define SIREN_E_PE_TRUNCATED     SIREN_MAKE_STATUS(0x02, 0x04)
#define SIREN_E_CARRIER_ALLOC    SIREN_MAKE_STATUS(0x03, 0x01)
#define SIREN_E_CARRIER_MAP      SIREN_MAKE_STATUS(0x03, 0x02)

/* ── Inject options (out-params filled by siren_inject) ───────────── */

typedef struct siren_inject_options {
    void   *out_stub_addr;
    size_t  out_entry_offset;
    void   *out_local_view;
    HANDLE  out_section;
    size_t  out_progress_offset;
} siren_inject_options;

/* ── Public API ───────────────────────────────────────────────────── */

siren_status_t siren_inject(HANDLE hProcess,
                            const void *pe_bytes, size_t pe_size,
                            siren_inject_options *opts);

#ifdef __cplusplus
}
#endif

#endif /* SIREN_H */
