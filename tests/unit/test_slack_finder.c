/*
 * tests/unit/test_slack_finder.c
 *
 * Q1: Does kernel32.dll have >= SIREN_STUB_MIN_SLACK bytes of slack?
 *     Validates the slack finder against the current process itself.
 */

#include "siren/siren.h"
#include "slack/slack_finder.h"

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

    void  *slack_addr = NULL;
    size_t slack_size = 0;
    siren_status_t r = siren_slack_find(hSelf, L"kernel32.dll",
                                        &slack_addr, &slack_size);

    CloseHandle(hSelf);

    if (SIREN_FAILED(r)) {
        fprintf(stderr, "FAIL: siren_slack_find: %s\n",
                siren_status_string(r));
        return 1;
    }

    printf("PASS: slack at %p, size = %zu bytes\n", slack_addr, slack_size);

    if (slack_size < SIREN_STUB_MIN_SLACK) {
        fprintf(stderr, "FAIL: slack too small (%zu < %u)\n",
                slack_size, SIREN_STUB_MIN_SLACK);
        return 1;
    }
    printf("PASS: slack >= SIREN_STUB_MIN_SLACK (%u)\n", SIREN_STUB_MIN_SLACK);
    return 0;
}
