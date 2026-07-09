# Windows Port Status

This repository is still primarily the original Unix AFLNet codebase. Native
Windows support is being added incrementally so Windows protocol targets can be
replayed first, then fuzzed through a Windows execution backend.

## What Works Now

- `afl-compat.h` provides a small portability layer for sockets, sleeps, binary
  file I/O flags, and Winsock initialization.
- `aflnet.c`, `afl-replay.c`, and `aflnet-replay.c` use the portability layer.
- The replay tools can be built as native Windows executables with a GNU-like C
  compiler.
- `aflnet-win-fuzz.exe` is a native Windows state-guided network fuzzer. It
  launches a Windows target process, mutates AFLNet request sequences, sends
  them over TCP or UDP, tracks unique protocol response-state sequences, and
  saves replayable crashing inputs when the process exits with a Windows
  exception status.
- With `--minidump`, launched targets run under the Windows debugging API and
  unique crash artifacts get a sibling `.dmp` file for WinDbg or Visual Studio.
- With `--crash-on-exit`, launched targets that exit nonzero are saved as
  crashes even when the exit code is not a Windows exception status.
- It also saves replayable hang inputs when a target has to be terminated after
  the configured `-t` window and no protocol response was observed.
- `--no-launch` lets the same network mutation loop fuzz an already-running
  target, which is useful for Windows services, GUI programs, or targets started
  under a separate debugger.
- `aflnet-win-fuzz.exe` also writes AFL-style run metadata to `fuzzer_stats`
  and keeps a raw `queue` corpus that is loaded on later runs with the same
  output directory.
- An optional raw bitmap-file feedback path is available with `-B`. The fuzzer
  tracks newly discovered nonzero bitmap bytes, persists that discovery state
  across resumed runs, and saves the first input that reaches new bitmap
  coverage.
- `examples\windows\aflnet_win_sancov.c` provides a basic clang
  SanitizerCoverage writer for rebuildable Windows targets.

## Building Windows Tools

Install CMake plus MinGW-w64 GCC or clang. MSVC is not supported for these
sources yet because the inherited AFL headers use GNU C extensions such as
statement expressions, `typeof`, and GNU variadic macros.

The quickest path is the PowerShell helper:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-win.ps1
```

It probes `PATH` plus common MSYS2, LLVM, CMake, Ninja, Chocolatey, and Scoop
install locations, then auto-selects Ninja or MinGW Makefiles if the matching
build tool is available. It checks for a GNU-like C compiler, sets `CC` to that
compiler when `CC` is not already set, prints the selected toolchain, and builds
the Windows tools into `build-win`. If MSYS2 is installed somewhere other than
`C:\msys64`, set `MSYS2_ROOT` to that install directory before running the
helper. If you want to force a specific compiler, set `CC` to the compiler
path, for example `$env:CC = 'C:\msys64\ucrt64\bin\gcc.exe'`.

Equivalent direct CMake commands:

```powershell
cmake -S . -B build-win -G "MinGW Makefiles"
cmake --build build-win
```

If you use Ninja instead of MinGW Makefiles:

```powershell
cmake -S . -B build-win -G Ninja
cmake --build build-win
```

The expected outputs are:

- `build-win\afl-replay.exe`
- `build-win\aflnet-replay.exe`
- `build-win\aflnet-win-fuzz.exe`
- `build-win\aflnet-win-rtsp-smoke.exe`
- `build-win\libaflnet-win-sancov.a` or the generator-specific equivalent

If you do not have MSYS2 or LLVM installed on the Windows host, Docker Desktop
can cross-build the same Windows `.exe` outputs with MinGW-w64:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-win-docker.ps1
```

The Docker helper builds `docker\windows-cross.Dockerfile`, bind-mounts this
repository at `/src`, and runs CMake with `x86_64-w64-mingw32-gcc`. It writes
the binaries to `build-win` on the host, so the normal smoke verifier can run
afterward. The Linux container is only for compilation; it cannot execute the
Windows smoke binaries.

Example:

```powershell
.\build-win\aflnet-replay.exe .\replayable-crashes\id_000000 RTSP 8554
.\build-win\aflnet-replay.exe .\replayable-crashes\id_000000 RTSP tcp://localhost/8554
```

## Smoke Test

The build includes `aflnet-win-rtsp-smoke.exe`, a tiny Windows-only RTSP-like
server for validating the native fuzzer before pointing it at a real Windows
application. It responds with distinct RTSP status codes for common RTSP
methods, so AFLNet can observe state changes, and it writes a small raw
coverage bitmap when `AFLNET_COVERAGE_FILE` is set by `aflnet-win-fuzz.exe -B`.

The automated smoke verifier runs seven deterministic checks: a TCP
state/coverage run, a UDP state/coverage run, a no-launch external-target run,
a dry-run corpus pass, an exception crash-artifact run, a nonzero-exit
crash-artifact run, and a hang-artifact run.

```powershell
powershell -ExecutionPolicy Bypass -File .\examples\windows\run_smoke.ps1 -Clean
```

On success it verifies that `states`, `coverage`, `coverage_bits.bin`,
`fuzzer_stats`, `exec_log.tsv`, `replayable-crashes`, and `hangs` artifacts were
produced under `out-smoke`, that discovery metadata sidecars exist, and that the
stats counters report at least one execution, TCP and UDP state signals, TCP and
UDP coverage signals, one no-launch run, one saved crash, and one saved hang
across the runs.
The crash smoke pass enables `--minidump` and checks for a `.dmp` beside the
packetized crash input.
The nonzero-exit crash pass enables `--crash-on-exit` and checks for
`crash_reason : nonzero_exit`.
The TCP smoke pass also uses `-E` to prove that target-specific environment
variables reach the launched Windows process.

Manual state/coverage smoke command:

```powershell
.\build-win\aflnet-win-fuzz.exe `
  -i .\tutorials\live555\in-rtsp `
  -o .\out-smoke `
  -N tcp://127.0.0.1/8554 `
  -P RTSP `
  -B .\out-smoke\coverage.bin `
  -C .\build-win `
  -E AFLNET_SMOKE_ENV_MARKER=.\out-smoke\target-env-marker.txt `
  -X .\tutorials\live555\rtsp.dict `
  -D 10000 `
  -x 200 `
  -- aflnet-win-rtsp-smoke.exe 8554
```

After the run, `out-smoke\states`, `out-smoke\coverage`, and
`out-smoke\fuzzer_stats` should show that the fuzzer launched a Windows
process, exchanged RTSP messages, extracted response-state feedback, and loaded
the optional bitmap feedback file.

Manual UDP state/coverage smoke command:

```powershell
.\build-win\aflnet-win-fuzz.exe `
  -i .\tutorials\live555\in-rtsp `
  -o .\out-smoke-udp `
  -N udp://127.0.0.1/8555 `
  -P RTSP `
  -B .\out-smoke-udp\coverage.bin `
  -C .\build-win `
  -D 10000 `
  -x 200 `
  -- aflnet-win-rtsp-smoke.exe 8555 udp
```

The bundled smoke server defaults to TCP. Passing `udp` as its second argument
makes it bind a UDP socket and answer each datagram with RTSP-style response
codes, which validates AFLNet's Windows UDP send/receive path.

Manual no-launch smoke command:

```powershell
$server = Start-Process -FilePath .\build-win\aflnet-win-rtsp-smoke.exe `
  -ArgumentList 8554 `
  -PassThru `
  -WindowStyle Hidden

.\build-win\aflnet-win-fuzz.exe `
  -i .\tutorials\live555\in-rtsp `
  -o .\out-smoke-no-launch `
  -N tcp://127.0.0.1/8554 `
  -P RTSP `
  -x 1 `
  --no-launch

Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
```

That run should set `no_launch : 1` and `target_path : external` in
`out-smoke-no-launch\fuzzer_stats`. In this mode AFLNet does not own the target
process, so it can still discover protocol response states and optional bitmap
coverage, but it cannot classify process crashes or kill-and-save hangs.

## Fuzzing a Windows Network Target

`aflnet-win-fuzz.exe` is intentionally narrower than Unix `afl-fuzz`: it is
state-guided and crash-detecting, but it does not include a built-in code
coverage backend yet. Use it for native Windows smoke fuzzing while the
coverage backend is still being ported. Each target execution is placed in a
Windows Job Object when the OS permits it, so helper child processes are also
cleaned up at the end of the iteration.

```powershell
.\build-win\aflnet-win-fuzz.exe `
  -i .\in-rtsp `
  -o .\out-win `
  -N tcp://127.0.0.1/8554 `
  -P RTSP `
  -D 10000 `
  -C .\live555\testProgs `
  -X .\tutorials\live555\rtsp.dict `
  -x 10000 `
  -V 3600 `
  -S 12345 `
  --minidump `
  --crash-on-exit `
  -- testOnDemandRTSPServer.exe 8554
```

Use `-N udp://host/port` instead for UDP services. The launched target command
is still responsible for binding that UDP port before the fuzzer's `-D` startup
delay expires.

Useful run controls:

- `--no-launch`: connect to an already-running target and omit the
  `-- target.exe` part of the command. This is useful for Windows services, GUI
  programs, targets started under WinDbg, or anything that needs a custom
  launcher. In this mode `-D`, `-C`, and `-t` do not control the external
  process, and crashes or hangs cannot be classified from process exit status.
  If you also use `-B`, start the external target with `AFLNET_COVERAGE_FILE`
  set to the same bitmap path before launching the fuzzer.
- `--minidump`: launch the target under the Windows debugging API and save a
  best-effort minidump when a second-chance crash exception is observed. This is
  useful for triage in WinDbg or Visual Studio. It can change behavior for
  debugger-sensitive targets and is not available with `--no-launch`.
- `--crash-on-exit`: treat nonzero target exit codes as crashes even when they
  are not Windows exception-like NTSTATUS values. This is useful for Windows
  harnesses, service wrappers, or assertion libraries that report failures with
  explicit process exit codes. It is opt-in because many network services exit
  nonzero for configuration or startup errors that are not fuzzing crashes.
- `-C dir`: launch the target with this working directory. This is useful for
  Windows apps that load config, DLLs, media files, or certificates relative to
  their build/install directory. If the target executable is relative and
  exists under `-C`, `aflnet-win-fuzz.exe` launches that file directly.
- `-E NAME=VALUE`: set a target environment variable for launched targets.
  Repeat it for multiple variables. This is useful for DLL search paths,
  sanitizer flags, feature toggles, or target-specific config. The fuzzer
  applies these variables only around `CreateProcess`, then restores its own
  process environment. `-E` is not available with `--no-launch`; set the
  environment before starting an external target yourself. When `-B` is used,
  the fuzzer also sets `AFLNET_COVERAGE_FILE` for launched targets.
- `-x count`: stop after this many executions. Use `-x 0` for no iteration
  limit.
- `-V seconds`: stop after this many seconds. Use `-V 0` for no time limit.
- `-X file`: load an AFL-style dictionary and use its tokens as overwrite
  mutations within AFLNet request regions. Quoted AFL dictionary entries such
  as `"OPTIONS"` and `method="DESCRIBE"` are supported, including common
  escapes like `\r`, `\n`, `\t`, `\"`, `\\`, and `\xHH`.
- `-Z`: dry-run mode. Launch the target once per loaded seed without mutation,
  write `exec_log.tsv` and `fuzzer_stats`, then stop with `stop_reason` set to
  `dry_run`. This is useful for validating the corpus, target startup delay,
  socket timeouts, and response parsing before fuzzing.
- Ctrl-C or Ctrl-Break requests a clean stop after the current execution.

Numeric options are parsed strictly; malformed or negative values fail fast
instead of silently becoming zero.

Output directories:

- `queue`: raw interesting inputs. A later run with the same `-o` directory
  loads these alongside the original `-i` seeds. During a fuzzing run, newly
  saved state or coverage queue entries are also added to the active mutation
  corpus immediately, so long runs can build on discoveries without requiring a
  restart.
- `queue_manifest.tsv`: append-only queue index with the queue id, discovery
  kind, queue path, source seed, signal hash, and signal detail for new state
  and coverage entries. The first row is a TSV header.
- `states`: first input for each unique response-state sequence. Each saved
  input gets a sibling `.txt` sidecar with the source seed, queue entry,
  signal hash, signal length, and state sequence string. State-derived filename
  components are shortened and sanitized for Windows; the sidecar and
  `queue_manifest.tsv` keep the full signal detail.
- `coverage`: first input that reaches newly discovered nonzero raw bitmap bytes
  when `-B` is enabled. Each saved input gets a sibling `.txt` sidecar with the
  source seed, queue entry, signal hash, bitmap length, and `new_bits=` count.
- `coverage_bits.bin`: persisted raw bitmap discovery state. A later run with
  the same `-o` directory loads this file before deciding whether a new `-B`
  bitmap contains previously unseen coverage.
- `replayable-crashes`: inputs where the target process exited with a Windows
  exception-like status, such as access violation or stack overflow. Each crash
  gets a sibling `.txt` file with the exit code, symbolic exit name, crash
  reason (`exception_status` or `nonzero_exit`), crash hash, target command,
  minidump path, and replay command, plus a `.replay.ps1` helper script. When
  `--minidump` is enabled and the dump succeeds, a sibling `.dmp` file is saved
  beside the crash input. Crash metadata and generated replay helpers include
  any `-E` variables used for the fuzzing run.
- `hangs`: inputs where the target had to be terminated after `-t` milliseconds
  and no protocol response was received. Each hang gets a sibling `.txt` file
  with the hang hash, timeout, target command, and replay command, plus a
  `.replay.ps1` helper script.
- `network-errors`: capped examples of inputs that could not be fully sent,
  useful for tuning startup delay, socket timeout, or target reliability.
- `exec_log.tsv`: append-only per-execution log with the seed path, outcome
  (`dry_run`, `ok`, `crash`, `hang`, `net_error`, or `no_response`), response
  byte count, response-state count, coverage byte count, newly discovered
  coverage bytes, exit code, target process id, timeout/send flags, crash
  reason, active corpus size, and cumulative discovery counters. If a resumed
  output directory contains an older incompatible header, the fuzzer rotates it
  to `exec_log.tsv.old-schema` before starting a fresh log with the current
  schema.
- `fuzzer_stats`: current run counters, target settings, timing metadata, and
  `stop_reason` (`running`, `dry_run`, `iteration_limit`, `time_limit`, or
  `signal`).
  `active_seeds` reports the live mutation corpus size, while `queued_paths`
  reports saved queue artifacts in the output directory.
  When `-B` is enabled, `coverage_bits_seen` reports the number of discovered
  nonzero bitmap bytes and `coverage_map_bytes` reports the persisted bitmap
  discovery file length. When `-X` is enabled, `dictionary_tokens` reports the
  number of usable tokens loaded from the dictionary file. `target_env_vars`
  reports the number of `-E` variables configured for launched targets, with
  `target_env_000`, `target_env_001`, and so on listing the exact assignments.
  `target_command` records the complete launched command line for reproducible
  handoff. When `--no-launch` is enabled, `no_launch` is `1` and `target_path`
  and `target_command` are `external`. When `--minidump` is enabled, `minidump`
  is `1`. When `--crash-on-exit` is enabled, `crash_on_exit` is `1`.
- `state_hashes.txt`, `coverage_hashes.txt`, `crash_hashes.txt`, and
  `hang_hashes.txt`:
  persisted discovery indexes used to avoid re-saving the same state,
  coverage, crash, or hang signal on resumed runs.

Crash or hang replay workflow:

```powershell
# Option A: use the generated helper script from replayable-crashes or hangs.
.\out-win\replayable-crashes\id_000000,exit_c0000005.replay.ps1 `
  -AFLNetReplay .\build-win\aflnet-replay.exe

# Option B: replay manually.
.\testOnDemandRTSPServer.exe 8554
.\build-win\aflnet-replay.exe .\out-win\replayable-crashes\id_000000,exit_c0000005 RTSP tcp://127.0.0.1/8554
```

If `--minidump` produced a sibling `.dmp`, open it directly in WinDbg or Visual
Studio for the crashing thread and module state. The replay command remains the
source of truth for reproducing the crash against a rebuilt target.

Optional clang SanitizerCoverage bitmap:

The repository includes `examples\windows\aflnet_win_sancov.c`, a small
SanitizerCoverage runtime for Windows targets built with clang. It implements
`trace-pc-guard` callbacks, creates or memory-maps the file named by
`AFLNET_COVERAGE_FILE`, and updates a raw 64 KiB bitmap that
`aflnet-win-fuzz.exe -B` can hash after each execution.

For a target you control, compile and link the target with clang coverage flags
and the runtime source:

```powershell
clang -g -O1 `
  -fsanitize-coverage=trace-pc-guard `
  .\my-server.c .\examples\windows\aflnet_win_sancov.c `
  -lws2_32 -o .\my-server.exe
```

Then run the fuzzer with `-B`:

```powershell
.\build-win\aflnet-win-fuzz.exe `
  -i .\in-rtsp `
  -o .\out-win `
  -N tcp://127.0.0.1/8554 `
  -P RTSP `
  -B .\coverage.bin `
  -X .\tutorials\live555\rtsp.dict `
  -- .\instrumented-server.exe 8554
```

The `-B` file is intentionally simple: the fuzzer deletes any stale bitmap
before launching the target, reads the file as raw bytes after each execution,
marks every newly discovered nonzero byte in `coverage_bits.bin`, and saves the
input when at least one byte is new. The path is normalized before launch and
inherited by the target as `AFLNET_COVERAGE_FILE`. The bundled SanitizerCoverage
runtime memory-maps that path when possible, so coverage can survive normal
fuzzer-driven process termination. Other instrumentation systems can write the
same raw file format without changing AFLNet's network mutation loop.

## What Does Not Work Yet

Native Windows coverage-guided `afl-fuzz.exe` is not complete. The original AFL
execution engine depends on Unix-only primitives:

- `fork()` and the AFL forkserver protocol
- SysV shared memory for coverage bitmaps
- `waitpid()`, Unix signals, and `setitimer()`
- Unix resource limits and `/proc` or `/sys` host checks

Those pieces need a Windows runner and coverage backend before this repo can
provide full AFL-style coverage-guided fuzzing for Windows applications.

## Recommended Next Porting Slice

The next useful milestone is deeper coverage-guided scheduling for Windows
targets:

- Factor the reusable mutation and queue pieces out of `afl-fuzz.c` so
  `aflnet-win-fuzz.exe` and Unix `afl-fuzz` can share more behavior.
- Feed the persisted coverage bitmap novelty into deeper AFL-style scheduling
  and power schedules instead of only using it as a second interesting-input
  signal.
- Add a DynamoRIO/WinAFL-style adapter for closed-source Windows targets that
  cannot be rebuilt with clang SanitizerCoverage.
- Preserve the replay format so crashes found on Windows can still be minimized
  and replayed with `aflnet-replay.exe`.
