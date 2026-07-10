# WinAFLNet Air-Gapped Windows Guide

This guide explains how to prepare WinAFLNet on an internet-connected staging
machine, transfer only the required artifacts, and run fuzzing on an
air-gapped Windows machine.

The recommended workflow is:

1. Build and smoke-test WinAFLNet on an online Windows staging machine.
2. Create a transfer bundle with the built `.exe` files, docs, dictionaries,
   seeds, and target application files.
3. Verify hashes on the air-gapped machine.
4. Run WinAFLNet from the transferred bundle.

Building directly on the air-gapped machine is possible, but it requires
offline installation of Docker Desktop or a full MinGW/LLVM toolchain. Prefer
transferring already-built WinAFLNet binaries unless you specifically need to
rebuild inside the air gap.

## What To Download On The Online Machine

Download or prepare these items before crossing the air gap.

Required for the recommended runtime-only bundle:

- This WinAFLNet repository.
- One Windows build path:
  - Docker Desktop for Windows, if you want to cross-build with
    `build-win-docker.ps1`; or
  - CMake plus Ninja or MinGW Makefiles plus MSYS2 MinGW-w64 GCC or LLVM clang,
    if you want to build with `build-win.ps1`.
- Your target Windows application, including all DLLs, config files, licenses,
  services, data directories, and installers it needs.
- Any target runtime redistributables that are not already present on the
  air-gapped machine, such as Visual C++ Redistributable installers, .NET
  offline installers, Java runtimes, Python embeddable runtimes, database
  engines, or vendor drivers.
- Seed corpus files for the target protocol.
- Optional AFL-style dictionaries, such as `tutorials\live555\rtsp.dict` for
  RTSP-like targets.
- Optional target coverage runtime pieces if you control and rebuild the target:
  `examples\windows\aflnet_win_sancov.c` and
  `build-win\libaflnet-win-sancov.a`.

Optional if you must build inside the air gap:

- Docker Desktop installer, including any organization-approved offline
  dependencies needed by Docker Desktop on that machine.
- A saved Docker image tar for `winaflnet/windows-cross:latest`, created with
  `docker save`, so the air-gapped machine does not need to pull packages.
- Or an offline host toolchain bundle: CMake, Ninja, MSYS2/MinGW-w64 or LLVM
  clang, and every package archive required by your organization to install
  those tools without internet access.

## Online Staging Build

Start from a clean checkout on the online Windows staging machine.

```powershell
cd E:\Developer\aflnet
git status --short --branch
```

Build with Docker Desktop:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build-win-docker.ps1
```

Or build with a host MinGW/LLVM toolchain:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build-win.ps1
```

Expected runtime files after a successful build:

- `build-win\afl-replay.exe`
- `build-win\aflnet-replay.exe`
- `build-win\aflnet-win-fuzz.exe`
- `build-win\aflnet-win-rtsp-smoke.exe`
- `build-win\libaflnet-win-sancov.a`

Run the smoke verifier on the online staging machine before transfer:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\examples\windows\run_smoke.ps1 -Clean
```

Do not skip this step. It proves the built Windows binaries can launch a target,
send TCP and UDP traffic, run `--no-launch`, save crash and hang artifacts, and
generate replay helpers.

## Create The Transfer Bundle

Create a directory that contains everything the air-gapped operator needs. This
example assumes your target files and seed corpus have already been staged under
`E:\TransferInputs`.

```powershell
cd E:\Developer\aflnet

$bundle = "E:\WinAFLNet-airgap-bundle"
$targetSource = "E:\TransferInputs\target"
$seedSource = "E:\TransferInputs\seeds"
$dictSource = "E:\TransferInputs\dicts"

if (Test-Path -LiteralPath $bundle) {
  throw "Bundle path already exists: $bundle"
}

New-Item -ItemType Directory -Force -Path $bundle | Out-Null
New-Item -ItemType Directory -Force -Path "$bundle\WinAFLNet" | Out-Null
New-Item -ItemType Directory -Force -Path "$bundle\target" | Out-Null
New-Item -ItemType Directory -Force -Path "$bundle\seeds" | Out-Null
New-Item -ItemType Directory -Force -Path "$bundle\dicts" | Out-Null

Copy-Item -Recurse -Force .\build-win "$bundle\WinAFLNet\build-win"
Copy-Item -Recurse -Force .\docs "$bundle\WinAFLNet\docs"
Copy-Item -Force .\README.md "$bundle\WinAFLNet\README.md"
Copy-Item -Force .\README-AFL.md "$bundle\WinAFLNet\README-AFL.md"
Copy-Item -Force .\LICENSE "$bundle\WinAFLNet\LICENSE"
Copy-Item -Recurse -Force .\examples "$bundle\WinAFLNet\examples"
Copy-Item -Recurse -Force .\tutorials "$bundle\WinAFLNet\tutorials"

Copy-Item -Recurse -Force $targetSource\* "$bundle\target"
Copy-Item -Recurse -Force $seedSource\* "$bundle\seeds"
if (Test-Path -LiteralPath $dictSource) {
  Copy-Item -Recurse -Force $dictSource\* "$bundle\dicts"
}

Get-ChildItem -LiteralPath $bundle -Recurse -File |
  Sort-Object FullName |
  ForEach-Object {
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName
    $relative = $_.FullName.Substring($bundle.Length).TrimStart('\')
    "{0}  {1}" -f $hash.Hash, $relative
  } |
  Set-Content -Encoding ascii -Path "$bundle\SHA256SUMS.txt"

Compress-Archive -LiteralPath $bundle -DestinationPath "$bundle.zip"
```

Transfer `E:\WinAFLNet-airgap-bundle.zip` to the air-gapped Windows machine by
your approved removable media or one-way transfer process.

## Optional: Transfer The Docker Build Image

Only do this if you must rebuild WinAFLNet inside the air gap with Docker
Desktop. It is not needed for normal fuzzing with the already-built `.exe`
files.

On the online staging machine:

```powershell
docker image inspect winaflnet/windows-cross:latest
docker save winaflnet/windows-cross:latest -o E:\WinAFLNet-airgap-bundle\winaflnet-windows-cross.tar
```

Add the Docker image tar to the bundle and regenerate `SHA256SUMS.txt`.

On the air-gapped machine, after Docker Desktop is installed and running:

```powershell
docker load -i .\winaflnet-windows-cross.tar
powershell -NoProfile -ExecutionPolicy Bypass -File .\WinAFLNet\build-win-docker.ps1 -SkipImageBuild
```

If Docker Desktop is not already approved for the air-gapped environment, avoid
this path. The runtime-only bundle is simpler and has fewer moving parts.

## Verify The Bundle Offline

On the air-gapped machine:

```powershell
New-Item -ItemType Directory -Force -Path C:\WinAFLNet | Out-Null
Expand-Archive -LiteralPath .\WinAFLNet-airgap-bundle.zip -DestinationPath C:\WinAFLNet
cd C:\WinAFLNet\WinAFLNet-airgap-bundle
```

Verify hashes before running anything:

```powershell
$root = (Get-Location).Path
$errors = 0

Get-Content .\SHA256SUMS.txt | ForEach-Object {
  if (-not $_.Trim()) { return }
  $parts = $_ -split "\s+", 2
  $expected = $parts[0]
  $relative = $parts[1]
  $path = Join-Path $root $relative

  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    Write-Host "MISSING $relative"
    $script:errors++
    return
  }

  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash
  if ($actual -ne $expected) {
    Write-Host "HASH MISMATCH $relative"
    $script:errors++
  }
}

if ($errors) {
  throw "Bundle verification failed with $errors error(s)"
}

Write-Host "Bundle verification passed"
```

## Offline Smoke Test

The smoke test does not require internet access. It only launches local Windows
executables and connects over loopback.

```powershell
cd C:\WinAFLNet\WinAFLNet-airgap-bundle\WinAFLNet
powershell -NoProfile -ExecutionPolicy Bypass -File .\examples\windows\run_smoke.ps1 -BuildDir .\build-win -OutDir .\out-smoke -Clean
```

Expected result:

```text
Windows smoke verification passed.
```

If the smoke test fails before your target is involved, fix that first. Common
causes are blocked execution policy, quarantined `.exe` files, missing runtime
DLLs, or endpoint protection blocking loopback network traffic.

## Run Against Your Target Offline

Use launched-target mode when WinAFLNet should start and stop the target for
each execution:

```powershell
cd C:\WinAFLNet\WinAFLNet-airgap-bundle

.\WinAFLNet\build-win\aflnet-win-fuzz.exe `
  -i .\seeds `
  -o .\out-my-target `
  -N tcp://127.0.0.1/9000 `
  -P RTSP `
  -C .\target `
  -D 250000 `
  -W 100 `
  -w 50000 `
  -t 1000 `
  -x 10000 `
  --minidump `
  -- target.exe --listen 9000
```

Adjust these values for your target:

- `-N`: protocol transport, host, and port.
- `-P`: parser name, such as `RTSP`, `HTTP`, `DNS`, `MQTT`, `SSH`, `TLS`, or
  `DTLS12`.
- `-C`: working directory for the target executable.
- `-D`: startup delay before WinAFLNet sends traffic.
- `-W`: response polling window in milliseconds.
- `-w`: socket send/receive timeout in microseconds.
- `-t`: target shutdown timeout in milliseconds.
- `--minidump`: save `.dmp` files beside crash reproducers.

Use `--no-launch` when the target is already running as a service, GUI app, or
debugger-owned process:

```powershell
.\WinAFLNet\build-win\aflnet-win-fuzz.exe `
  -i .\seeds `
  -o .\out-external `
  -N tcp://127.0.0.1/9000 `
  -P RTSP `
  -D 0 `
  -W 50 `
  -w 10000 `
  --no-launch
```

In `--no-launch` mode, WinAFLNet can still mutate inputs, send traffic, record
responses, and save state discoveries. It cannot classify process crashes or
kill-and-save hangs because it does not own the target process.

## Replay Findings Offline

Crash and hang artifacts are saved under the output directory:

- `out-my-target\replayable-crashes`
- `out-my-target\hangs`

Each finding has:

- a packetized replay input,
- a `.txt` metadata file,
- and a `.replay.ps1` helper.

Replay with the generated helper:

```powershell
.\out-my-target\replayable-crashes\id_000000,exit_c0000005,hash_12345678.replay.ps1 `
  -AFLNetReplay .\WinAFLNet\build-win\aflnet-replay.exe
```

Or replay manually after starting the target:

```powershell
.\WinAFLNet\build-win\aflnet-replay.exe `
  .\out-my-target\replayable-crashes\id_000000,exit_c0000005,hash_12345678 `
  RTSP `
  tcp://127.0.0.1/9000 `
  100 `
  50000
```

## Export Findings From The Air Gap

Follow your organization's export process. At minimum, export:

- The exact WinAFLNet commit or repository bundle used.
- `out-my-target\fuzzer_stats`.
- `out-my-target\exec_log.tsv`.
- Any files under `replayable-crashes`, `hangs`, and `network-errors` that you
  need to triage.
- Target version, target command line, config files, and seed corpus used for
  the run.
- Minidumps (`.dmp`) if `--minidump` was enabled and your export process allows
  them.

Before exporting, assume crash inputs, minidumps, logs, and target configs may
contain sensitive data from the air-gapped environment.

## Troubleshooting Offline Runs

`Windows smoke binaries were not found`

- Confirm `WinAFLNet\build-win` was included in the bundle.
- Confirm the bundle was extracted without antivirus quarantine.

`The target starts but WinAFLNet reports network errors`

- Confirm the target binds to the same host and port used by `-N`.
- Prefer `127.0.0.1` for local targets.
- Increase `-D` if the target needs more startup time.
- Check local firewall or endpoint protection rules.

`No new states are discovered`

- Confirm the `-P` parser matches the target protocol.
- Confirm seeds contain complete client requests.
- Preserve CRLF line endings for text protocols that require them.
- Add a dictionary with `-X` for text protocols with stable verbs or headers.

`No crash artifacts are saved`

- Use launched-target mode instead of `--no-launch`.
- Add `--crash-on-exit` if the target reports failures through nonzero exit
  codes rather than Windows exceptions.
- Add `--minidump` if you need debugger-friendly dumps.

`Replay does not reproduce`

- Confirm the target version, command line, working directory, environment, and
  timing flags match the fuzzing run.
- Use the generated `.replay.ps1` helper first; it preserves the original
  target arguments and replay timing.
