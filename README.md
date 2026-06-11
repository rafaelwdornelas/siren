# Siren

**A novel Windows DLL injection technique by Rafael Dornelas.**

Siren combines two original primitives never previously described in public
security research:

1. **Section Slack Carrier** — uses the zero-padding at the end of PE sections
   (`.data` slack space) in an already-loaded module as the code carrier.
   No `VirtualAllocEx`. No new VAD node. The memory type stays `MEM_IMAGE`.

2. **LdrpDllNotificationList Hijacking** — inserts a forged
   `_LDR_DLL_NOTIFICATION_ENTRY` into Windows NT's internal loader notification
   list. The payload fires on the next DLL load in the target — without
   `CreateRemoteThread`, `NtQueueApcThread`, or any remote thread at all.

The injector closes all handles and **exits immediately** after four
`WriteProcessMemory` calls. The payload DLL remains loaded in the target
indefinitely.

## IOC Profile

| Observable | Classic techniques | Siren |
|---|---|---|
| `VirtualAllocEx` | Yes | **No** |
| `CreateRemoteThread` | Yes | **No** |
| `NtQueueApcThread` | Yes | **No** |
| `NtCreateSection(SEC_IMAGE)` | Yes | **No** |
| `PsSetLoadImageNotifyRoutine` fires | Yes | **No** |
| New VAD node | Yes | **No** |
| Memory type of stub | `MEM_PRIVATE` | **`MEM_IMAGE`** |
| Injector must stay alive | Sometimes | **Never** |

## Build

Cross-compile on Linux (MinGW):

```bash
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-x86_64.cmake \
  -DSIREN_BUILD_POC=ON
cmake --build build
```

Or native Windows (MSVC or MinGW-w64):

```bash
cmake -B build -DSIREN_BUILD_POC=ON
cmake --build build
```

Requires CMake 3.20+, a C11 compiler, and Windows SDK (or MinGW-w64).

## Usage

```bash
# Inject payload.dll into process with PID 1234
build/poc/siren_injector.exe 1234 build/poc/siren_payload.dll

# The injector exits immediately.
# The payload writes %TEMP%\siren_proof.txt when triggered.
```

## Structure

```
include/siren/     — public API headers
src/
  pe/              — PE parser (adapted from Wraith)
  runtime/         — PEB walker
  slack/           — section slack finder
  handoff/         — NtCreateSection + DuplicateHandle
  notify/          — LdrpDllNotificationList probe + insert
  reflective/      — standalone reflective loader (C)
  stub/            — PIC assembly stub + serialiser
poc/               — proof-of-concept injector + payload DLL
tests/unit/        — unit tests for each subsystem
doc/TECHNIQUE.md   — full technical write-up
```

## Technical Write-up

See [doc/TECHNIQUE.md](doc/TECHNIQUE.md) for the complete analysis, including:

- Background on `LdrpDllNotificationList` and why it was never weaponised before
- Step-by-step technique description
- IOC profile comparison table
- Experimental validation results (Q1–Q5)
- Limitations (ACG, PPL, CFG)
- Comparison with Eclipse, Mockingjay, Early Cascade, and others

## Author

**Rafael Dornelas** — security researcher.

Technique coined and implemented in 2025. Both primitives (Section Slack Carrier
and LdrpDllNotificationList Hijacking) and their combination for fire-and-forget
injection are original contributions not found in prior public research.

## License

MIT — see [LICENSE](LICENSE).

Educational and research use only.
