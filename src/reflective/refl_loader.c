/*
 * src/reflective/refl_loader.c
 *
 * Reflective PE loader — runs inside the target process.
 *
 * This implementation is intentionally self-contained: it only uses
 * ntdll.dll functions (found via PEB walk) and performs no Win32 calls
 * that would require kernel32.dll to be fully initialised beforehand.
 *
 * Pipeline:
 *   1. Validate the PE view (DOS + NT magic, machine = AMD64)
 *   2. NtAllocateVirtualMemory for SizeOfImage bytes
 *   3. Copy headers + sections into the new allocation
 *   4. Apply base relocations (DIR64 only)
 *   5. Resolve import table (PEB walk per DLL + export table walk per name)
 *   6. Flush instruction cache
 *   7. Call DllMain(DLL_PROCESS_ATTACH)
 */

#include "reflective/refl_loader.h"
#include "pe/pe_parse.h"

#include <windows.h>
#include <winternl.h>
#include <string.h>

/* ── Nt function typedefs (resolved via GetProcAddress on ntdll) ─── */

typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(
    HANDLE Process, PVOID *Base, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocType, ULONG Protect);

typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(
    HANDLE Process, PVOID *Base, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

typedef NTSTATUS (NTAPI *PFN_NtFlushInstructionCache)(
    HANDLE Process, PVOID Base, ULONG Size);

typedef BOOL (WINAPI *DLL_ENTRY_POINT)(HINSTANCE, DWORD, LPVOID);

#define DLL_PROCESS_ATTACH_LOCAL 1u

/* ── Minimal export-table resolver ─────────────────────────────── */

static void *resolve_export(const uint8_t *mod_base, const char *func_name)
{
    const sr_pe_dos_hdr  *dos = (const sr_pe_dos_hdr *)mod_base;
    if (dos->e_magic != SIREN_PE_DOS_SIG)
        return NULL;

    const sr_pe_nt_hdrs64 *nt =
        (const sr_pe_nt_hdrs64 *)(mod_base + dos->e_lfanew);
    if (nt->Signature != SIREN_PE_NT_SIG)
        return NULL;

    uint32_t exp_rva  = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    uint32_t exp_size = nt->OptionalHeader.DataDirectory[0].Size;
    if (!exp_rva || !exp_size)
        return NULL;

    typedef struct {
        uint32_t Characteristics, TimeDateStamp;
        uint16_t MajorVersion, MinorVersion;
        uint32_t Name, Base;
        uint32_t NumberOfFunctions, NumberOfNames;
        uint32_t AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
    } ExportDir;

    const ExportDir *exp =
        (const ExportDir *)(mod_base + exp_rva);

    const uint32_t *names =
        (const uint32_t *)(mod_base + exp->AddressOfNames);
    const uint16_t *ordinals =
        (const uint16_t *)(mod_base + exp->AddressOfNameOrdinals);
    const uint32_t *funcs =
        (const uint32_t *)(mod_base + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const char *name_ptr = (const char *)(mod_base + names[i]);
        if (strcmp(name_ptr, func_name) == 0) {
            uint32_t rva = funcs[ordinals[i]];
            /* Check for forwarder (RVA inside export directory). */
            if (rva >= exp_rva && rva < exp_rva + exp_size)
                return NULL;  /* forwarders not resolved here */
            return (void *)(mod_base + rva);
        }
    }
    return NULL;
}

/* ── PEB-based module finder (no GetModuleHandle) ─────────────── */

typedef struct sr_ldr_entry_min {
    LIST_ENTRY     InLoadOrder;
    LIST_ENTRY     InMemoryOrder;
    LIST_ENTRY     InInitOrder;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} sr_ldr_entry_min;

#define ENTRY_FROM_INMEM(p) \
    ((sr_ldr_entry_min *)((uint8_t *)(p) - \
        offsetof(sr_ldr_entry_min, InMemoryOrder)))

static void *find_module_base(const char *name_a)
{
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    PLIST_ENTRY head = &((PPEB_LDR_DATA)peb->Ldr)->InMemoryOrderModuleList;
    PLIST_ENTRY cur  = head->Flink;

    while (cur != head) {
        sr_ldr_entry_min *e = ENTRY_FROM_INMEM(cur);
        if (e->BaseDllName.Buffer) {
            /* Simple ASCII comparison (module names are ASCII-safe). */
            const wchar_t *wn = e->BaseDllName.Buffer;
            const char    *an = name_a;
            int match = 1;
            while (*an && *wn) {
                char a = (char)((*an >= 'A' && *an <= 'Z') ?
                                 *an + 32 : *an);
                char b = (char)((*wn >= L'A' && *wn <= L'Z') ?
                                 *wn + 32 : *wn);
                if (a != (char)b) { match = 0; break; }
                ++an; ++wn;
            }
            if (match && *an == '\0' && *wn == L'\0' &&
                (uintptr_t)e->DllBase >= 0x10000u)
                return e->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

/* ── Main reflective load function ──────────────────────────────── */

siren_status_t sr_refl_load(const void *section_view, size_t view_size)
{
    if (!section_view || view_size < sizeof(sr_pe_dos_hdr))
        return SIREN_E_NULL_ARG;

    /* ── 1. Validate PE ───────────────────────────────────────────── */
    sr_pe_view pv;
    siren_status_t r = sr_pe_validate(section_view, view_size, &pv);
    if (SIREN_FAILED(r))
        return r;

    /* ── Resolve Nt functions we need ─────────────────────────────── */
    const uint8_t *ntdll = (const uint8_t *)find_module_base("ntdll.dll");
    if (!ntdll)
        return SIREN_E_MODULE_NOT_FOUND;

    PFN_NtAllocateVirtualMemory  NtAlloc =
        (PFN_NtAllocateVirtualMemory)
        resolve_export(ntdll, "NtAllocateVirtualMemory");
    PFN_NtProtectVirtualMemory   NtProtect =
        (PFN_NtProtectVirtualMemory)
        resolve_export(ntdll, "NtProtectVirtualMemory");
    PFN_NtFlushInstructionCache  NtFlush =
        (PFN_NtFlushInstructionCache)
        resolve_export(ntdll, "NtFlushInstructionCache");

    if (!NtAlloc || !NtProtect || !NtFlush)
        return SIREN_E_MODULE_NOT_FOUND;

    /* ── 2. Allocate memory for the loaded image ──────────────────── */
    SIZE_T   image_size = pv.nt->OptionalHeader.SizeOfImage;
    PVOID    image_base = (PVOID)pv.nt->OptionalHeader.ImageBase;

    NTSTATUS st = NtAlloc(
        (HANDLE)-1,     /* current process */
        &image_base,
        0, &image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (st < 0) {
        /* Preferred base busy — let the OS choose. */
        image_base = NULL;
        image_size = pv.nt->OptionalHeader.SizeOfImage;
        st = NtAlloc((HANDLE)-1, &image_base, 0, &image_size,
                     MEM_COMMIT | MEM_RESERVE,
                     PAGE_EXECUTE_READWRITE);
        if (st < 0)
            return SIREN_E_HANDOFF_ALLOC;
    }

    uint8_t *img = (uint8_t *)image_base;

    /* ── 3. Copy headers ──────────────────────────────────────────── */
    memcpy(img, section_view,
           pv.nt->OptionalHeader.SizeOfHeaders);

    /* ── 3b. Copy sections ────────────────────────────────────────── */
    const uint8_t *src = (const uint8_t *)section_view;
    for (uint16_t i = 0; i < pv.section_count; ++i) {
        const sr_pe_section_hdr *s = &pv.sections[i];
        if (!s->SizeOfRawData)
            continue;
        memcpy(img + s->VirtualAddress,
               src + s->PointerToRawData,
               s->SizeOfRawData);
    }

    /* ── 4. Base relocations ──────────────────────────────────────── */
    uint32_t reloc_rva, reloc_size;
    sr_pe_get_dir(&pv, SIREN_PE_DIR_BASERELOC, &reloc_rva, &reloc_size);

    int64_t delta = (int64_t)((uintptr_t)img -
                              pv.nt->OptionalHeader.ImageBase);

    if (reloc_rva && reloc_size && delta != 0) {
        uint8_t *end = img + reloc_rva + reloc_size;
        sr_pe_base_reloc *blk = (sr_pe_base_reloc *)(img + reloc_rva);
        while ((uint8_t *)blk < end && blk->SizeOfBlock >= 8) {
            uint16_t entries = (uint16_t)((blk->SizeOfBlock - 8) / 2);
            uint16_t *entry  = (uint16_t *)((uint8_t *)blk + 8);
            for (uint16_t j = 0; j < entries; ++j) {
                uint16_t type = entry[j] >> 12;
                uint16_t off  = entry[j] & 0x0fff;
                if (type == SIREN_PE_REL_DIR64) {
                    uint64_t *target =
                        (uint64_t *)(img + blk->VirtualAddress + off);
                    *target = (uint64_t)((int64_t)*target + delta);
                }
            }
            blk = (sr_pe_base_reloc *)((uint8_t *)blk + blk->SizeOfBlock);
        }
    }

    /* ── 5. Import table resolution ──────────────────────────────── */
    uint32_t imp_rva, imp_size;
    sr_pe_get_dir(&pv, SIREN_PE_DIR_IMPORT, &imp_rva, &imp_size);

    if (imp_rva && imp_size) {
        sr_pe_import_desc *desc =
            (sr_pe_import_desc *)(img + imp_rva);

        while (desc->Name) {
            const char *dll_name = (const char *)(img + desc->Name);
            const uint8_t *dep_base =
                (const uint8_t *)find_module_base(dll_name);

            if (!dep_base) {
                /* Fallback: LoadLibraryA if available. */
                HMODULE k32 = (HMODULE)find_module_base("kernel32.dll");
                if (k32) {
                    typedef HMODULE (WINAPI *PFN_LoadLibA)(const char *);
                    PFN_LoadLibA LoadLib =
                        (PFN_LoadLibA)resolve_export(
                            (const uint8_t *)k32, "LoadLibraryA");
                    if (LoadLib)
                        dep_base = (const uint8_t *)LoadLib(dll_name);
                }
            }

            uint64_t *thunk = (uint64_t *)(img +
                (desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                          : desc->FirstThunk));
            uint64_t *iat   = (uint64_t *)(img + desc->FirstThunk);

            while (*thunk) {
                void *func = NULL;
                if (*thunk & 0x8000000000000000ULL) {
                    /* Import by ordinal. */
                    uint16_t ord = (uint16_t)(*thunk & 0xffff);
                    if (dep_base) {
                        const sr_pe_nt_hdrs64 *dnt =
                            (const sr_pe_nt_hdrs64 *)(dep_base +
                                ((const sr_pe_dos_hdr *)dep_base)->e_lfanew);
                        uint32_t exp_rva_ =
                            dnt->OptionalHeader.DataDirectory[0].VirtualAddress;
                        if (exp_rva_) {
                            typedef struct {
                                uint32_t c, t; uint16_t maj, min;
                                uint32_t nm, base, nf, nn, af, an, ao;
                            } XDir;
                            const XDir *xd =
                                (const XDir *)(dep_base + exp_rva_);
                            const uint32_t *fns =
                                (const uint32_t *)(dep_base + xd->af);
                            uint32_t idx = ord - (uint16_t)xd->base;
                            if (idx < xd->nf)
                                func = (void *)(dep_base + fns[idx]);
                        }
                    }
                } else {
                    /* Import by name (hint + name). */
                    const char *name_ =
                        (const char *)(img + (*thunk & 0x7fffffffffffffffULL) + 2);
                    if (dep_base)
                        func = resolve_export(dep_base, name_);
                }
                *iat = func ? (uint64_t)(uintptr_t)func : 0;
                ++thunk; ++iat;
            }
            ++desc;
        }
    }

    /* ── 6. Flush instruction cache ──────────────────────────────── */
    NtFlush((HANDLE)-1, img,
            (ULONG)pv.nt->OptionalHeader.SizeOfImage);

    /* ── 7. Call DllMain ──────────────────────────────────────────── */
    uint32_t ep_rva = pv.nt->OptionalHeader.AddressOfEntryPoint;
    if (ep_rva) {
        DLL_ENTRY_POINT entry =
            (DLL_ENTRY_POINT)(img + ep_rva);
        entry((HINSTANCE)img, DLL_PROCESS_ATTACH_LOCAL, NULL);
    }

    return SIREN_OK;
}
