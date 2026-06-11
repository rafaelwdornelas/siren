/*
 * src/pe/pe_parse.h
 *
 * Self-contained PE constants and lightweight validator.
 * Adapted from Wraith (https://github.com/RafaelDornelas/Wraith)
 * with prefix changes wr_ → sr_ / WRAITH_ → SIREN_.
 *
 * Purposely free of <windows.h> so the parser is fuzzable on Linux.
 */

#ifndef SIREN_PE_PARSE_H
#define SIREN_PE_PARSE_H

#include "siren/siren_status.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Magic / machine constants ─────────────────────────────────────── */
#define SIREN_PE_DOS_SIG       0x5A4Du
#define SIREN_PE_NT_SIG        0x00004550u
#define SIREN_PE_OPT_PE32PLUS  0x020Bu
#define SIREN_PE_MACHINE_AMD64 0x8664u

/* ── Section characteristics ───────────────────────────────────────── */
#define SIREN_PE_SCN_MEM_EXECUTE  0x20000000u
#define SIREN_PE_SCN_MEM_READ     0x40000000u
#define SIREN_PE_SCN_MEM_WRITE    0x80000000u

/* ── Data directory indices ────────────────────────────────────────── */
#define SIREN_PE_DIR_IMPORT    1u
#define SIREN_PE_DIR_BASERELOC 5u
#define SIREN_PE_DIR_COUNT     16u

/* ── Relocation type ───────────────────────────────────────────────── */
#define SIREN_PE_REL_ABSOLUTE  0u
#define SIREN_PE_REL_DIR64     10u  /* x64 only */

#define SIREN_PE_SECTION_NAME_LEN 8u

#pragma pack(push, 1)

typedef struct sr_pe_dos_hdr {
    uint16_t e_magic;
    uint16_t _pad[29];
    uint32_t e_lfanew;
} sr_pe_dos_hdr;

typedef struct sr_pe_file_hdr {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} sr_pe_file_hdr;

typedef struct sr_pe_data_dir {
    uint32_t VirtualAddress;
    uint32_t Size;
} sr_pe_data_dir;

typedef struct sr_pe_opt_hdr64 {
    uint16_t        Magic;
    uint8_t         MajorLinkerVersion;
    uint8_t         MinorLinkerVersion;
    uint32_t        SizeOfCode;
    uint32_t        SizeOfInitializedData;
    uint32_t        SizeOfUninitializedData;
    uint32_t        AddressOfEntryPoint;
    uint32_t        BaseOfCode;
    uint64_t        ImageBase;
    uint32_t        SectionAlignment;
    uint32_t        FileAlignment;
    uint16_t        MajorOperatingSystemVersion;
    uint16_t        MinorOperatingSystemVersion;
    uint16_t        MajorImageVersion;
    uint16_t        MinorImageVersion;
    uint16_t        MajorSubsystemVersion;
    uint16_t        MinorSubsystemVersion;
    uint32_t        Win32VersionValue;
    uint32_t        SizeOfImage;
    uint32_t        SizeOfHeaders;
    uint32_t        CheckSum;
    uint16_t        Subsystem;
    uint16_t        DllCharacteristics;
    uint64_t        SizeOfStackReserve;
    uint64_t        SizeOfStackCommit;
    uint64_t        SizeOfHeapReserve;
    uint64_t        SizeOfHeapCommit;
    uint32_t        LoaderFlags;
    uint32_t        NumberOfRvaAndSizes;
    sr_pe_data_dir  DataDirectory[SIREN_PE_DIR_COUNT];
} sr_pe_opt_hdr64;

typedef struct sr_pe_nt_hdrs64 {
    uint32_t        Signature;
    sr_pe_file_hdr  FileHeader;
    sr_pe_opt_hdr64 OptionalHeader;
} sr_pe_nt_hdrs64;

typedef struct sr_pe_section_hdr {
    uint8_t  Name[SIREN_PE_SECTION_NAME_LEN];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} sr_pe_section_hdr;

typedef struct sr_pe_base_reloc {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
    /* uint16_t TypeOffset[]; */
} sr_pe_base_reloc;

/* Import descriptor */
typedef struct sr_pe_import_desc {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} sr_pe_import_desc;

#pragma pack(pop)

/* ── View: validated PE snapshot ──────────────────────────────────── */

typedef struct sr_pe_view {
    const uint8_t        *buffer;
    size_t                buffer_size;
    const sr_pe_dos_hdr  *dos;
    const sr_pe_nt_hdrs64 *nt;
    const sr_pe_section_hdr *sections;
    uint16_t              section_count;
} sr_pe_view;

/* Validate a complete PE32+ (x64) file/buffer and fill *out.
 * Checks that every section's raw data fits within buf_size.
 * Returns SIREN_OK or a SIREN_E_PE_* error. */
siren_status_t sr_pe_validate(const void *buf, size_t buf_size, sr_pe_view *out);

/* Simplified version — just validates, no view output. */
siren_status_t sr_pe_validate_quick(const void *buf, size_t buf_size);

/* Validate only the PE header region (DOS + NT headers + section table).
 * Does NOT require section raw data to fit in buf_size.
 * Use this when buf is a partial header read from a mapped remote module. */
siren_status_t sr_pe_parse_headers(const void *buf, size_t buf_size,
                                   sr_pe_view *out);

/* Get data directory entry safely. Outputs 0,0 when the entry is absent. */
void sr_pe_get_dir(const sr_pe_view *v, unsigned idx,
                   uint32_t *out_rva, uint32_t *out_size);

/* Align value up to the given power-of-two alignment. */
static inline uint32_t sr_pe_align_up(uint32_t v, uint32_t align)
{
    return (v + align - 1u) & ~(align - 1u);
}

#ifdef __cplusplus
}
#endif

#endif /* SIREN_PE_PARSE_H */
