/*
 * src/pe/pe_parse.c
 *
 * Bounds-checked PE32+ validator and helper functions.
 * Adapted from Wraith — all pointer arithmetic is overflow-guarded.
 */

#include "pe/pe_parse.h"

#include <string.h>

static int u32_add_overflows(uint32_t a, uint32_t b)
{
    return b > (uint32_t)0xffffffffu - a;
}

static int range_exceeds(size_t a, size_t b, size_t limit)
{
    if (b > limit)
        return 1;
    return a > limit - b;
}

static int is_pow2(uint32_t v)
{
    return v != 0 && (v & (v - 1)) == 0;
}

siren_status_t sr_pe_validate(const void *buf, size_t buf_size, sr_pe_view *out)
{
    if (!buf || !out)
        return SIREN_E_NULL_ARG;

    memset(out, 0, sizeof(*out));

    if (buf_size < sizeof(sr_pe_dos_hdr))
        return SIREN_E_PE_TRUNCATED;

    const uint8_t      *bytes = (const uint8_t *)buf;
    const sr_pe_dos_hdr *dos  = (const sr_pe_dos_hdr *)bytes;

    if (dos->e_magic != SIREN_PE_DOS_SIG)
        return SIREN_E_PE_BAD_DOS;

    uint32_t nt_off = dos->e_lfanew;
    if (nt_off < sizeof(sr_pe_dos_hdr))
        return SIREN_E_PE_TRUNCATED;
    if (range_exceeds(nt_off, sizeof(sr_pe_nt_hdrs64), buf_size))
        return SIREN_E_PE_TRUNCATED;

    const sr_pe_nt_hdrs64 *nt = (const sr_pe_nt_hdrs64 *)(bytes + nt_off);
    if (nt->Signature != SIREN_PE_NT_SIG)
        return SIREN_E_PE_BAD_NT;
    if (nt->FileHeader.Machine != SIREN_PE_MACHINE_AMD64)
        return SIREN_E_PE_WRONG_ARCH;
    if (nt->OptionalHeader.Magic != SIREN_PE_OPT_PE32PLUS)
        return SIREN_E_PE_WRONG_ARCH;

    if (!is_pow2(nt->OptionalHeader.SectionAlignment) ||
        !is_pow2(nt->OptionalHeader.FileAlignment) ||
        nt->OptionalHeader.SectionAlignment < nt->OptionalHeader.FileAlignment)
        return SIREN_E_PE_BAD_NT;

    uint32_t sec_off = nt_off
        + (uint32_t)offsetof(sr_pe_nt_hdrs64, OptionalHeader)
        + nt->FileHeader.SizeOfOptionalHeader;

    uint16_t sec_count = nt->FileHeader.NumberOfSections;
    if (sec_count == 0)
        return SIREN_E_PE_BAD_NT;

    size_t sec_bytes = (size_t)sec_count * sizeof(sr_pe_section_hdr);
    if (range_exceeds(sec_off, sec_bytes, buf_size))
        return SIREN_E_PE_TRUNCATED;

    const sr_pe_section_hdr *sections =
        (const sr_pe_section_hdr *)(bytes + sec_off);

    for (uint16_t i = 0; i < sec_count; ++i) {
        const sr_pe_section_hdr *s = &sections[i];
        if (s->SizeOfRawData > 0) {
            if (u32_add_overflows(s->PointerToRawData, s->SizeOfRawData))
                return SIREN_E_PE_TRUNCATED;
            if ((size_t)(s->PointerToRawData + s->SizeOfRawData) > buf_size)
                return SIREN_E_PE_TRUNCATED;
        }
    }

    out->buffer        = bytes;
    out->buffer_size   = buf_size;
    out->dos           = dos;
    out->nt            = nt;
    out->sections      = sections;
    out->section_count = sec_count;
    return SIREN_OK;
}

siren_status_t sr_pe_validate_quick(const void *buf, size_t buf_size)
{
    sr_pe_view v;
    return sr_pe_validate(buf, buf_size, &v);
}

void sr_pe_get_dir(const sr_pe_view *v, unsigned idx,
                   uint32_t *out_rva, uint32_t *out_size)
{
    *out_rva  = 0;
    *out_size = 0;
    if (!v || !v->nt || idx >= SIREN_PE_DIR_COUNT)
        return;
    if (idx >= v->nt->OptionalHeader.NumberOfRvaAndSizes)
        return;
    *out_rva  = v->nt->OptionalHeader.DataDirectory[idx].VirtualAddress;
    *out_size = v->nt->OptionalHeader.DataDirectory[idx].Size;
}
