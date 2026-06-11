#include "siren/siren_status.h"

const char *siren_status_string(siren_status_t s)
{
    switch (s) {
    case SIREN_OK:                  return "SIREN_OK";
    case SIREN_E_NULL_ARG:          return "SIREN_E_NULL_ARG";
    case SIREN_E_BAD_SIZE:          return "SIREN_E_BAD_SIZE";
    case SIREN_E_PE_BAD_DOS:        return "SIREN_E_PE_BAD_DOS";
    case SIREN_E_PE_BAD_NT:         return "SIREN_E_PE_BAD_NT";
    case SIREN_E_PE_WRONG_ARCH:     return "SIREN_E_PE_WRONG_ARCH";
    case SIREN_E_PE_TRUNCATED:      return "SIREN_E_PE_TRUNCATED";
    case SIREN_E_PE_NO_RELOCS:      return "SIREN_E_PE_NO_RELOCS";
    case SIREN_E_SLACK_NOT_FOUND:   return "SIREN_E_SLACK_NOT_FOUND";
    case SIREN_E_SLACK_TOO_SMALL:   return "SIREN_E_SLACK_TOO_SMALL";
    case SIREN_E_SLACK_READ:        return "SIREN_E_SLACK_READ";
    case SIREN_E_NOTIFY_NO_NTDLL:   return "SIREN_E_NOTIFY_NO_NTDLL";
    case SIREN_E_NOTIFY_REG_FAIL:   return "SIREN_E_NOTIFY_REG_FAIL";
    case SIREN_E_NOTIFY_WRITE:      return "SIREN_E_NOTIFY_WRITE";
    case SIREN_E_HANDOFF_ALLOC:     return "SIREN_E_HANDOFF_ALLOC";
    case SIREN_E_HANDOFF_MAP:       return "SIREN_E_HANDOFF_MAP";
    case SIREN_E_HANDOFF_DUP:       return "SIREN_E_HANDOFF_DUP";
    case SIREN_E_STUB_TOO_LARGE:    return "SIREN_E_STUB_TOO_LARGE";
    case SIREN_E_STUB_WRITE:        return "SIREN_E_STUB_WRITE";
    case SIREN_E_OPEN_PROCESS:      return "SIREN_E_OPEN_PROCESS";
    case SIREN_E_MODULE_NOT_FOUND:  return "SIREN_E_MODULE_NOT_FOUND";
    default:                        return "(unknown siren status)";
    }
}
