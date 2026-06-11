/*
 * src/reflective/refl_loader.h
 *
 * Standalone reflective PE loader.
 *
 * Designed to be called from inside the target process (by the PIC stub)
 * after the PE payload section has been mapped.  Performs:
 *   1. Base relocations (IMAGE_REL_BASED_DIR64 only — x64)
 *   2. Import resolution (via PEB walk + export table walk)
 *   3. Section permission finalisation (RX for .text, RW for .data, etc.)
 *   4. TLS callbacks (if present)
 *   5. DllMain(DLL_PROCESS_ATTACH)
 *
 * This C version is compiled into the static library.  The assembly stub
 * (siren_stub_x64.S) embeds a position-independent copy at link time.
 */

#ifndef SIREN_REFL_LOADER_H
#define SIREN_REFL_LOADER_H

#include "siren/siren_status.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * sr_refl_load
 *
 * Load the PE image whose raw bytes begin at `section_view` (a
 * NtMapViewOfSection view of the pagefile section).
 *
 * Returns SIREN_OK on success.  The DLL is loaded at a new private
 * allocation; `section_view` is not modified.
 *
 * Called from inside the target process (notification callback).
 */
siren_status_t sr_refl_load(const void *section_view, size_t view_size);

#ifdef __cplusplus
}
#endif

#endif /* SIREN_REFL_LOADER_H */
