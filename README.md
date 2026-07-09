# WinAFLNet

WinAFLNet is a Windows-focused fork of
[AFLNet](https://github.com/aflnet/aflnet), the state-aware greybox fuzzer for
network protocol implementations. The goal of this fork is practical Windows
target fuzzing: build native Windows tools, launch or attach to Windows network
applications, mutate AFLNet-style request sequences, track protocol-state
feedback, and save replayable crash and hang artifacts.

The original AFLNet project was designed for Unix-like systems. WinAFLNet keeps
the AFLNet protocol parsers and request-region model, then adds a native Windows
execution backend around Win32 process control, Winsock, crash classification,
minidump collection, and PowerShell-friendly workflows.

## Status

Working now:

- Native Windows replay tools: `afl-replay.exe` and `aflnet-replay.exe`.
- Native Windows state-guided network fuzzer: `aflnet-win-fuzz.exe`.
- TCP and UDP target communication through Winsock.
- Launched-target mode for ordinary Windows executables.
- `--no-launch` mode for already-running services, GUI apps, or debugger-owned
  targets.
- Crash artifacts for Windows exception exits.
- Optional `--minidump` crash dumps.
- Optional `--crash-on-exit` for targets that signal failure with nonzero exit
  codes.
- Hang artifacts when the target must be killed and no protocol response was
  observed.
- AFL-style dictionaries for request-region mutations.
- Optional raw bitmap feedback with `-B`.
- Resumable `queue`, `coverage_bits.bin`, `exec_log.tsv`, and `fuzzer_stats`
  outputs.
- Docker Desktop cross-build path for machines without MSYS2 or LLVM installed.
- Deterministic Windows smoke tests in `examples\windows`.

Still intentionally limited:

- The classic Unix `afl-fuzz` forkserver/shared-memory backend is not a native
  Windows `afl-fuzz.exe` replacement.
- Code coverage is optional and target-provided. Use `-B` with a target that
  writes a raw bitmap file, or link the sample SanitizerCoverage runtime into a
  rebuildable target.
- MSVC is not supported for these inherited AFL/AFLNet sources because they use
  GNU C extensions.

## Repository Layout

- `aflnet-win-fuzz.c`: native Windows fuzzer.
- `afl-compat.h`: portability layer for sockets, sleeps, binary I/O flags, and
  Winsock initialization.
- `aflnet.c`, `aflnet.h`: AFLNet protocol parsing, request extraction, state
  extraction, and shared network helpers.
- `afl-replay.c`, `aflnet-replay.c`: replay utilities.
- `CMakeLists.txt`: Windows-tool build graph.
- `build-win.ps1`: host build helper for MSYS2/LLVM/CMake/Ninja setups.
- `build-win-docker.ps1`: Docker Desktop MinGW cross-build helper.
- `docker\windows-cross.Dockerfile`: Debian plus MinGW-w64/CMake/Ninja image.
- `examples\windows\rtsp_smoke_server.c`: tiny Windows RTSP-like test target.
- `examples\windows\aflnet_win_sancov.c`: sample raw-bitmap coverage writer.
- `examples\windows\run_smoke.ps1`: full Windows smoke verifier.
- `docs\windows_port.md`: detailed implementation notes and option reference.
- `tutorials\live555`: upstream AFLNet RTSP tutorial assets and dictionary.

## Requirements

Use one of these build paths.

Docker Desktop path:

- Windows 10/11.
- PowerShell.
- Docker Desktop running in Linux-container mode.
- Internet access the first time, so Docker can pull Debian packages.

Host toolchain path:

- Windows 10/11.
- PowerShell.
- CMake.
- Ninja or MinGW Makefiles.
- MSYS2 MinGW-w64 GCC or LLVM clang on `PATH`.

Runtime smoke testing requires no Docker once the `.exe` files exist. The smoke
suite runs the generated Windows binaries directly on the Windows host.

## Quick Start

From the repository root:

```powershell
cd E:\Developer\aflnet
```

Build with Docker Desktop:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-win-docker.ps1
```

This builds `winaflnet/windows-cross:latest`, mounts the repository into the
container, and writes Windows binaries to `build-win`.

Build with a host MinGW/LLVM toolchain instead:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-win.ps1
```

Expected outputs:

- `build-win\afl-replay.exe`
- `build-win\aflnet-replay.exe`
- `build-win\aflnet-win-fuzz.exe`
- `build-win\aflnet-win-rtsp-smoke.exe`
- `build-win\libaflnet-win-sancov.a`

Run the Windows smoke suite:

```powershell
powershell -ExecutionPolicy Bypass -File .\examples\windows\run_smoke.ps1 -Clean
```

The smoke suite verifies TCP, UDP, no-launch mode, dry-run mode, state
discovery, optional bitmap coverage, corpus growth, crash artifacts, minidumps,
nonzero-exit crash handling, hang artifacts, replay helper generation,
environment-variable propagation, log schema rotation, queue-manifest schema
rotation, file-path clean refusal, and resume counters.

## Walkthrough: Fuzz The Included Smoke Target

The smoke target is a tiny RTSP-like Windows server. It is not a real RTSP
implementation; it exists to prove the fuzzer can drive a Windows process.

Create a minimal RTSP seed:

```powershell
New-Item -ItemType Directory -Force -Path .\seeds-rtsp | Out-Null
@"
OPTIONS rtsp://127.0.0.1:8554/smoke RTSP/1.0
CSeq: 1

DESCRIBE rtsp://127.0.0.1:8554/smoke RTSP/1.0
CSeq: 2

"@ -replace "`r?`n", "`r`n" |
  Set-Content -NoNewline -Encoding ascii .\seeds-rtsp\basic.raw
```

Run a short fuzzing session:

```powershell
.\build-win\aflnet-win-fuzz.exe `
  -i .\seeds-rtsp `
  -o .\out-win-smoke `
  -N tcp://127.0.0.1/8554 `
  -P RTSP `
  -C .\build-win `
  -D 100000 `
  -W 50 `
  -w 10000 `
  -x 200 `
  -X .\tutorials\live555\rtsp.dict `
  -- aflnet-win-rtsp-smoke.exe 8554
```

Useful flags in that command:

- `-i`: seed corpus directory.
- `-o`: output directory.
- `-N`: network target as `tcp://host/port` or `udp://host/port`.
- `-P`: protocol parser. `RTSP` is used by the smoke target.
- `-C`: target working directory.
- `-D`: target startup delay in microseconds before sending traffic.
- `-W`: response polling window in milliseconds.
- `-w`: socket send/receive timeout in microseconds.
- `-x`: number of executions.
- `-X`: AFL-style dictionary file.
- `--`: everything after this is the target command.

Inspect the results:

```powershell
Get-Content .\out-win-smoke\fuzzer_stats
Get-Content .\out-win-smoke\exec_log.tsv
Get-ChildItem .\out-win-smoke\states
Get-ChildItem .\out-win-smoke\queue
```

Resume the same campaign by reusing `-o .\out-win-smoke`. WinAFLNet reloads
saved queue entries and persisted coverage-bit state.

## Walkthrough: Fuzz Your Own Windows App

1. Confirm the target is network reachable.

   Start the application normally and make sure a client can connect to it on
   `127.0.0.1` or the host/IP you plan to fuzz.

2. Pick a supported protocol parser.

   Common parser names include `RTSP`, `FTP`, `SMTP`, `DNS`, `SIP`, `HTTP`,
   `TLS`, `DTLS12`, `DICOM`, `MQTT`, `SSH`, `IPP`, `TFTP`, `SNTP`, `NTP`, and
   `SNMP`. The parser controls request splitting and response-state extraction.

3. Build a seed corpus.

   Seeds are raw client request streams. For text protocols, a seed can often
   be created by saving a normal client conversation as ASCII. For binary
   protocols, capture one or more valid client request sequences and save the
   request bytes.

   Place seeds in a directory:

   ```powershell
   New-Item -ItemType Directory -Force -Path .\my-seeds | Out-Null
   Copy-Item .\captured-request.raw .\my-seeds\
   ```

4. Run a dry pass first.

   Dry-run mode validates startup timing, request parsing, network settings,
   and response-state extraction without mutation.

   ```powershell
   .\build-win\aflnet-win-fuzz.exe `
     -i .\my-seeds `
     -o .\out-my-target `
     -N tcp://127.0.0.1/9000 `
     -P RTSP `
     -C C:\path\to\target `
     -D 250000 `
     -W 100 `
     -w 50000 `
     -Z `
     -- target.exe --listen 9000
   ```

5. Start fuzzing.

   ```powershell
   .\build-win\aflnet-win-fuzz.exe `
     -i .\my-seeds `
     -o .\out-my-target `
     -N tcp://127.0.0.1/9000 `
     -P RTSP `
     -C C:\path\to\target `
     -D 250000 `
     -W 100 `
     -w 50000 `
     -t 1000 `
     -x 10000 `
     --minidump `
     -- target.exe --listen 9000
   ```

6. Review findings.

   Crashes appear under `out-my-target\replayable-crashes`. Hangs appear under
   `out-my-target\hangs`. Each finding has a packetized replay file plus a
   `.txt` metadata sidecar. Crash and hang artifacts also get a `.replay.ps1`
   helper.

## Already-Running Targets

Use `--no-launch` when WinAFLNet should not start or stop the target. This is
useful for Windows services, GUI applications, targets started by another
supervisor, or programs running under WinDbg/Visual Studio.

Start the target yourself, then run:

```powershell
.\build-win\aflnet-win-fuzz.exe `
  -i .\my-seeds `
  -o .\out-external `
  -N tcp://127.0.0.1/9000 `
  -P RTSP `
  -D 0 `
  -W 50 `
  -w 10000 `
  --no-launch
```

In this mode WinAFLNet still mutates inputs, sends traffic, records responses,
saves state discoveries, and grows the queue. Process crash/hang classification
is not available because WinAFLNet does not own the process.

## Optional Coverage Feedback

Protocol-state feedback works without code coverage. If you can instrument or
modify the target, `-B` adds a simple file-backed bitmap signal.

Run the fuzzer with a bitmap path:

```powershell
.\build-win\aflnet-win-fuzz.exe `
  -i .\my-seeds `
  -o .\out-with-coverage `
  -N tcp://127.0.0.1/9000 `
  -P RTSP `
  -B .\out-with-coverage\coverage.bin `
  -C C:\path\to\target `
  -- target.exe --listen 9000
```

For launched targets, WinAFLNet sets `AFLNET_COVERAGE_FILE` to the normalized
bitmap path. The target should write a raw bitmap to that file before exit.
Nonzero bytes are treated as covered bytes. New bytes are persisted in
`coverage_bits.bin`, and the first input reaching new bitmap bytes is saved
under `coverage`.

For clang-built targets, see `examples\windows\aflnet_win_sancov.c` and link
`build-win\libaflnet-win-sancov.a` into a target compiled with:

```powershell
-fsanitize-coverage=trace-pc-guard
```

## Target Environment Variables

Use `-E NAME=VALUE` to set environment variables only around the launched
target process:

```powershell
.\build-win\aflnet-win-fuzz.exe `
  -i .\my-seeds `
  -o .\out-env `
  -N tcp://127.0.0.1/9000 `
  -P RTSP `
  -E MY_TARGET_MODE=fuzz `
  -- target.exe --listen 9000
```

Environment variables are restored in the fuzzer process after each launch.
`-E` is intentionally rejected with `--no-launch`, because WinAFLNet cannot
change the environment of an already-running process.

## Output Directory Guide

Important files and directories under `-o`:

- `queue`: raw interesting inputs loaded again on resume.
- `queue_manifest.tsv`: queue id, discovery kind, source seed, signal hash,
  and signal detail.
- `states`: first input for each unique response-state sequence.
- `coverage`: first input reaching new raw bitmap bytes when `-B` is enabled.
- `coverage_bits.bin`: persisted bitmap discovery state.
- `replayable-crashes`: packetized crash reproducers plus metadata and replay
  helpers.
- `hangs`: packetized hang reproducers plus metadata and replay helpers.
- `network-errors`: capped examples of send/connect failures.
- `exec_log.tsv`: one row per execution with outcome, response bytes, state
  count, coverage bytes, exit code, target PID, timeout/send flags, crash
  reason, and cumulative counters.
- `fuzzer_stats`: current run settings and counters.

State-derived filename components are sanitized for Windows. The full state
detail is kept in metadata and `queue_manifest.tsv`.

## Replaying Findings

Crash and hang metadata include a manual replay command. You can also run the
generated helper:

```powershell
.\out-my-target\replayable-crashes\id_000000,exit_c0000005,hash_12345678.replay.ps1 `
  -AFLNetReplay .\build-win\aflnet-replay.exe
```

Manual replay:

```powershell
.\build-win\aflnet-replay.exe `
  .\out-my-target\replayable-crashes\id_000000,exit_c0000005,hash_12345678 `
  RTSP `
  tcp://127.0.0.1/9000 `
  50 `
  10000
```

For raw non-packetized request streams, use `afl-replay.exe` instead.

## Practical Tuning

- Increase `-D` if the fuzzer connects before the target is listening.
- Increase `-W` if responses arrive after the polling window.
- Increase `-w` if sends or receives time out too aggressively.
- Use `-t` to control how long launched targets may run after traffic is sent.
- Use `--crash-on-exit` for targets that report failures with nonzero exits.
- Use `--minidump` when you want debugger-friendly `.dmp` files.
- Keep the same `-o` directory to resume and grow the corpus.
- Add dictionaries with `-X` for text protocols with stable verbs, headers, or
  magic values.
- Start with `-Z` dry runs before long fuzzing sessions.

## Troubleshooting

`No GNU-like C compiler was found`

Install MSYS2 MinGW-w64 GCC/LLVM, or use:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-win-docker.ps1
```

`Windows smoke binaries were not found`

Build first:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-win-docker.ps1
```

No responses or too many network errors:

- Verify host/port in `-N`.
- Increase `-D`.
- Check whether the target binds to `127.0.0.1` or another interface.
- Confirm Windows Firewall is not blocking local connections.

No new states:

- Confirm the selected `-P` parser matches the protocol.
- Check that seeds contain complete request messages.
- For line protocols, preserve required CRLF terminators.

No crash artifacts even though the target fails:

- Use `--crash-on-exit` for nonzero exits.
- Use launched-target mode instead of `--no-launch` if WinAFLNet must classify
  process exits.
- Check `exec_log.tsv` for `exit_code`, `send_failed`, and
  `target_timed_out`.

## Upstream AFLNet Notes

WinAFLNet is derived from AFLNet and keeps the upstream protocol-fuzzing model:
mutate request sequences, send them to a server, observe response codes as
state feedback, and preserve inputs that discover new behavior.

The original AFLNet publication:

```bibtex
@inproceedings{AFLNet,
author={Van{-}Thuan Pham and Marcel B{\"o}hme and Abhik Roychoudhury},
title={AFLNet: A Greybox Fuzzer for Network Protocols},
booktitle={Proceedings of the 13rd IEEE International Conference on Software Testing, Verification and Validation : Testing Tools Track},
year={2020},}
```

American Fuzzy Lop background remains in [README-AFL.md](README-AFL.md).
The original Linux-oriented AFLNet tutorials are still useful for learning seed
capture and protocol-state concepts, but this README is the starting point for
Windows target fuzzing with WinAFLNet.

## License

This fork keeps the original Apache License, Version 2.0 licensing terms. See
[LICENSE](LICENSE).
