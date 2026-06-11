#ifndef SIREN_TYPES_H
#define SIREN_TYPES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimum slack space required to hold stub + reflective loader + notify entry. */
#define SIREN_STUB_MIN_SLACK  1024u

/* Depth cap for import resolution loops (prevents cycles). */
#define SIREN_IMPORT_MAX_DEPTH  32u

/*
 * Options passed to siren_inject().
 *
 * All fields are optional — zero-initialise and override only what you need.
 */
typedef struct siren_inject_options {
    /* Name of the already-loaded module whose .data slack will carry the stub.
     * If NULL, defaults to L"kernel32.dll". */
    const wchar_t *carrier_module;

    /* If non-zero, print diagnostic lines to stderr during injection. */
    int            verbose;
} siren_inject_options;

#ifdef __cplusplus
}
#endif

#endif /* SIREN_TYPES_H */
