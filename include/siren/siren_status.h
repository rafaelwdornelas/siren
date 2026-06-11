#ifndef SIREN_STATUS_H
#define SIREN_STATUS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t siren_status_t;

/* Category encoding — upper byte of the status code. */
#define SIREN_CAT(s)           (((s) >> 24) & 0xff)
#define SIREN_MAKE_STATUS(cat, sub) \
    (((siren_status_t)(cat) << 24) | (siren_status_t)(sub))

#define SIREN_SUCCESS(s)  ((s) == 0)
#define SIREN_FAILED(s)   ((s) != 0)

/* Categories */
#define SIREN_CAT_OK          0x00
#define SIREN_CAT_INVALID_ARG 0x01
#define SIREN_CAT_PE_FORMAT   0x02
#define SIREN_CAT_MAPPING     0x03
#define SIREN_CAT_SLACK       0x04
#define SIREN_CAT_NOTIFY      0x05
#define SIREN_CAT_HANDOFF     0x06
#define SIREN_CAT_STUB        0x07
#define SIREN_CAT_RUNTIME     0x08
#define SIREN_CAT_INTERNAL    0x0f

/* Success */
#define SIREN_OK  ((siren_status_t)0)

/* Generic errors */
#define SIREN_E_NULL_ARG       SIREN_MAKE_STATUS(SIREN_CAT_INVALID_ARG, 0x01)
#define SIREN_E_BAD_SIZE       SIREN_MAKE_STATUS(SIREN_CAT_INVALID_ARG, 0x02)

/* PE format errors */
#define SIREN_E_PE_BAD_DOS     SIREN_MAKE_STATUS(SIREN_CAT_PE_FORMAT, 0x01)
#define SIREN_E_PE_BAD_NT      SIREN_MAKE_STATUS(SIREN_CAT_PE_FORMAT, 0x02)
#define SIREN_E_PE_WRONG_ARCH  SIREN_MAKE_STATUS(SIREN_CAT_PE_FORMAT, 0x03)
#define SIREN_E_PE_TRUNCATED   SIREN_MAKE_STATUS(SIREN_CAT_PE_FORMAT, 0x04)
#define SIREN_E_PE_NO_RELOCS   SIREN_MAKE_STATUS(SIREN_CAT_PE_FORMAT, 0x05)

/* Slack space errors */
#define SIREN_E_SLACK_NOT_FOUND SIREN_MAKE_STATUS(SIREN_CAT_SLACK, 0x01)
#define SIREN_E_SLACK_TOO_SMALL SIREN_MAKE_STATUS(SIREN_CAT_SLACK, 0x02)
#define SIREN_E_SLACK_READ      SIREN_MAKE_STATUS(SIREN_CAT_SLACK, 0x03)

/* Notification list errors */
#define SIREN_E_NOTIFY_NO_NTDLL SIREN_MAKE_STATUS(SIREN_CAT_NOTIFY, 0x01)
#define SIREN_E_NOTIFY_REG_FAIL SIREN_MAKE_STATUS(SIREN_CAT_NOTIFY, 0x02)
#define SIREN_E_NOTIFY_WRITE    SIREN_MAKE_STATUS(SIREN_CAT_NOTIFY, 0x03)

/* Section handoff errors */
#define SIREN_E_HANDOFF_ALLOC   SIREN_MAKE_STATUS(SIREN_CAT_HANDOFF, 0x01)
#define SIREN_E_HANDOFF_MAP     SIREN_MAKE_STATUS(SIREN_CAT_HANDOFF, 0x02)
#define SIREN_E_HANDOFF_DUP     SIREN_MAKE_STATUS(SIREN_CAT_HANDOFF, 0x03)

/* Stub errors */
#define SIREN_E_STUB_TOO_LARGE  SIREN_MAKE_STATUS(SIREN_CAT_STUB, 0x01)
#define SIREN_E_STUB_WRITE      SIREN_MAKE_STATUS(SIREN_CAT_STUB, 0x02)

/* Runtime errors */
#define SIREN_E_OPEN_PROCESS    SIREN_MAKE_STATUS(SIREN_CAT_RUNTIME, 0x01)
#define SIREN_E_MODULE_NOT_FOUND SIREN_MAKE_STATUS(SIREN_CAT_RUNTIME, 0x02)

#ifdef __cplusplus
}
#endif

#endif /* SIREN_STATUS_H */
