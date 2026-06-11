/*
 * tests/unit/test_notify_list.c
 *
 * Q5: Can we locate LdrpDllNotificationList in ntdll?
 *     Validates the list head discovery against the current process.
 */

#include "siren/siren.h"
#include "notify/ldr_notify.h"

#include <stdio.h>
#include <windows.h>

int main(void)
{
    HANDLE hSelf = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, GetCurrentProcessId());

    if (!hSelf) {
        fprintf(stderr, "FAIL: OpenProcess self: %lu\n", GetLastError());
        return 1;
    }

    void *list_head = NULL;
    siren_status_t r = siren_notify_find_list_head(hSelf, &list_head);

    CloseHandle(hSelf);

    if (SIREN_FAILED(r)) {
        fprintf(stderr, "FAIL: siren_notify_find_list_head: %s (0x%X)\n",
                siren_status_string(r), (unsigned)r);
        return 1;
    }

    printf("PASS: LdrpDllNotificationList found at %p\n", list_head);

    /* Sanity: must be in ntdll's address range */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    uintptr_t ntdll_base = (uintptr_t)ntdll;
    MODULEINFO mi = { 0 };
    if (GetModuleInformation(GetCurrentProcess(), ntdll,
                             &mi, sizeof(mi))) {
        uintptr_t lh = (uintptr_t)list_head;
        if (lh >= ntdll_base && lh < ntdll_base + mi.SizeOfImage) {
            printf("PASS: address is within ntdll image range\n");
        } else {
            fprintf(stderr, "WARN: address outside ntdll range — check offsets\n");
        }
    }

    return 0;
}
