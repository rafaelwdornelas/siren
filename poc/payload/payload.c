/*
 * poc/payload/payload.c
 *
 * Siren Injection — test payload DLL.
 *
 * On DLL_PROCESS_ATTACH, writes a proof-of-execution file to %TEMP%.
 * Used to verify the full injection chain end-to-end.
 */

#include <windows.h>
#include <stdio.h>

static void write_proof(void)
{
    wchar_t temp[MAX_PATH];
    wchar_t path[MAX_PATH];

    if (!GetTempPathW(MAX_PATH, temp))
        return;

    _snwprintf(path, MAX_PATH, L"%ssiren_proof.txt", temp);

    HANDLE hf = CreateFileW(path,
                            GENERIC_WRITE,
                            0, NULL,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
    if (hf == INVALID_HANDLE_VALUE)
        return;

    char msg[] = "Siren Injection — DLL loaded successfully.\r\n"
                 "Author: Rafael Dornelas\r\n"
                 "Technique: LdrpDllNotificationList Hijacking\r\n";

    DWORD written;
    WriteFile(hf, msg, (DWORD)(sizeof(msg) - 1), &written, NULL);
    CloseHandle(hf);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH)
        write_proof();

    return TRUE;
}
