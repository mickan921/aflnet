# WinAFLNet Windows Examples

This directory contains tiny native Windows targets used to validate the
WinAFLNet Windows fuzzing path.

## SanitizerCoverage Runtime

`aflnet_win_sancov.c` is a small clang SanitizerCoverage runtime for Windows
targets. Link it into a target built with
`-fsanitize-coverage=trace-pc-guard`, then run `aflnet-win-fuzz.exe -B
.\coverage.bin`. The fuzzer exports the normalized bitmap path as
`AFLNET_COVERAGE_FILE`, and the runtime memory-maps that file when possible.
`aflnet-win-fuzz.exe` treats nonzero bitmap bytes as discovered coverage,
persists them in `coverage_bits.bin`, and saves inputs only when a run reaches
previously unseen bytes.

## RTSP Smoke Server

`rtsp_smoke_server.c` builds as `aflnet-win-rtsp-smoke.exe` through the root
CMake project. It is not a full RTSP server; it is a deterministic target for
checking that `aflnet-win-fuzz.exe` can launch a Windows process, connect over
TCP, send AFLNet RTSP request regions, extract response-state feedback, and
optionally consume a raw bitmap through `AFLNET_COVERAGE_FILE`.
Pass `udp` as the second runtime argument to exercise the same response logic
over UDP datagrams.
If `AFLNET_SMOKE_ENV_MARKER` is present in the target environment, the server
writes that marker file; the smoke script uses this to verify `-E` propagation.
The smoke script also starts the server outside the fuzzer once and verifies
`--no-launch`, which is the mode to use for already-running Windows services or
targets launched under a debugger.

Example after building:

```powershell
powershell -ExecutionPolicy Bypass -File .\examples\windows\run_smoke.ps1 -Clean
```

The script verifies TCP and UDP state, coverage, persisted coverage-bit state,
queue manifest, active corpus growth, no-launch mode, dry-run mode, crash hash
indexing, crash minidumps, nonzero-exit crash handling, target environment
propagation, replay-helper, discovery metadata, crash metadata, hang metadata,
dictionary loading, `exec_log.tsv` target PID/crash-reason fields, and
`fuzzer_stats` target command/environment fields.

Manual equivalent:

```powershell
.\build-win\aflnet-win-fuzz.exe `
  -i .\tutorials\live555\in-rtsp `
  -o .\out-smoke `
  -N tcp://127.0.0.1/8554 `
  -P RTSP `
  -B .\out-smoke\coverage.bin `
  -C .\build-win `
  -X .\tutorials\live555\rtsp.dict `
  -x 200 `
  -- aflnet-win-rtsp-smoke.exe 8554
```

UDP equivalent:

```powershell
.\build-win\aflnet-win-fuzz.exe `
  -i .\tutorials\live555\in-rtsp `
  -o .\out-smoke-udp `
  -N udp://127.0.0.1/8555 `
  -P RTSP `
  -B .\out-smoke-udp\coverage.bin `
  -C .\build-win `
  -x 200 `
  -- aflnet-win-rtsp-smoke.exe 8555 udp
```
