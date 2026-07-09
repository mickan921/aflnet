param(
  [string]$BuildDir = "build-win",
  [string]$OutDir = "out-smoke",
  [int]$Port = 8554,
  [switch]$Clean
)

$ErrorActionPreference = "Stop"

function Resolve-RepoPath($Path) {
  if ([System.IO.Path]::IsPathRooted($Path)) {
    return [System.IO.Path]::GetFullPath($Path)
  }

  return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
}

function Assert-Path($Path, $Description) {
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "Missing $Description at $Path"
  }
}

function Assert-DirectoryHasFiles($Path, $Description) {
  Assert-Path $Path $Description

  $count = @(Get-ChildItem -LiteralPath $Path -File -ErrorAction Stop).Count
  if ($count -lt 1) {
    throw "$Description did not contain any files: $Path"
  }
}

function Assert-TextContains($Path, $Pattern, $Description) {
  if (-not (Select-String -LiteralPath $Path -Pattern $Pattern -Quiet)) {
    throw "$Description did not contain pattern '$Pattern': $Path"
  }
}

function Assert-Throws($ScriptBlock, $Pattern, $Description) {
  try {
    & $ScriptBlock
  } catch {
    if ($_.Exception.Message -match $Pattern) {
      return
    }

    throw "$Description failed with unexpected error: $($_.Exception.Message)"
  }

  throw "$Description did not fail"
}

function Assert-ReplayHelperCommon($Path, [switch]$ExpectTargetEnv) {
  $null = [scriptblock]::Create((Get-Content -Raw -LiteralPath $Path))
  Assert-TextContains $Path "Start-Sleep -Milliseconds 100" "replay helper"
  Assert-TextContains $Path '\[System\.Diagnostics\.ProcessStartInfo\]::new\(\)' "replay helper"
  Assert-TextContains $Path 'ArgumentList\.Add\(\$arg\)' "replay helper argument preservation"
  Assert-TextContains $Path "'50', '10000'\)" "replay helper timeout preservation"
  Assert-TextContains $Path '\$replayStartInfo\.FileName\s*=\s*\$AFLNetReplay' "replay helper replay path"

  if ($ExpectTargetEnv) {
    Assert-TextContains $Path '\$targetStartInfo\.UseShellExecute\s*=\s*\$false' "replay helper target environment"
    Assert-TextContains $Path '\$targetStartInfo\.EnvironmentVariables\[\$name\]\s*=\s*\$targetEnv\[\$name\]' "replay helper target environment"
  }
}

function Assert-CrashArtifactSet($Path, [switch]$ExpectMinidump, [string]$ExpectedEnv = "", [string]$ExpectedReason = "") {
  Assert-Path $Path "crash smoke replayable-crashes"

  $crashInputs = @(Get-ChildItem -LiteralPath $Path -File -ErrorAction Stop |
    Where-Object {
      $_.Name -notlike "*.txt" -and
      $_.Name -notlike "*.ps1" -and
      $_.Name -notlike "*.dmp"
    })

  if ($crashInputs.Count -lt 1) {
    throw "No packetized crash input was saved in $Path"
  }

  $crashInput = $crashInputs[0].FullName
  $metadata = "$crashInput.txt"
  $replayScript = "$crashInput.replay.ps1"
  $minidump = "$crashInput.dmp"

  Assert-Path $metadata "crash metadata"
  Assert-Path $replayScript "crash replay helper"
  if ($ExpectMinidump) {
    Assert-Path $minidump "crash minidump"
  }
  Assert-TextContains $metadata "^exit_code\s*:" "crash metadata"
  Assert-TextContains $metadata "^exit_name\s*:" "crash metadata"
  Assert-TextContains $metadata "^crash_hash\s*:" "crash metadata"
  Assert-TextContains $metadata "^poll_wait_msecs\s*:\s*50\s*$" "crash metadata"
  Assert-TextContains $metadata "^socket_timeout_us\s*:\s*10000\s*$" "crash metadata"
  if ($ExpectedReason) {
    Assert-TextContains $metadata "^crash_reason\s*:\s*$([regex]::Escape($ExpectedReason))\s*$" "crash metadata"
  }
  if ($ExpectMinidump) {
    Assert-TextContains $metadata "^minidump\s*:.*\.dmp\s*$" "crash metadata"
  }
  if ($ExpectedEnv) {
    Assert-TextContains $metadata "^target_env_vars\s*:\s*1\s*$" "crash metadata"
    Assert-TextContains $metadata "^target_env_000\s*:\s*$([regex]::Escape($ExpectedEnv))\s*$" "crash metadata"
  }
  Assert-TextContains $metadata "^manual_replay_cmd\s*:.*\s50\s+10000\s*$" "crash metadata"

  Assert-ReplayHelperCommon $replayScript -ExpectTargetEnv:([bool]$ExpectedEnv)
}

function Assert-HangArtifactSet($Path) {
  Assert-Path $Path "hang smoke hangs"

  $hangInputs = @(Get-ChildItem -LiteralPath $Path -File -ErrorAction Stop |
    Where-Object { $_.Name -notlike "*.txt" -and $_.Name -notlike "*.ps1" })

  if ($hangInputs.Count -lt 1) {
    throw "No packetized hang input was saved in $Path"
  }

  $hangInput = $hangInputs[0].FullName
  $metadata = "$hangInput.txt"
  $replayScript = "$hangInput.replay.ps1"

  Assert-Path $metadata "hang metadata"
  Assert-Path $replayScript "hang replay helper"
  Assert-TextContains $metadata "^hang_hash\s*:" "hang metadata"
  Assert-TextContains $metadata "^timeout_ms\s*:" "hang metadata"
  Assert-TextContains $metadata "^poll_wait_msecs\s*:\s*50\s*$" "hang metadata"
  Assert-TextContains $metadata "^socket_timeout_us\s*:\s*10000\s*$" "hang metadata"
  Assert-TextContains $metadata "^manual_replay_cmd\s*:.*\s50\s+10000\s*$" "hang metadata"

  Assert-ReplayHelperCommon $replayScript
}

function Assert-DiscoveryMetadata($Path, $Kind) {
  Assert-Path $Path "$Kind artifacts"

  $artifacts = @(Get-ChildItem -LiteralPath $Path -File -ErrorAction Stop |
    Where-Object { $_.Name -notlike "*.txt" -and $_.Name -notlike "*.ps1" })

  if ($artifacts.Count -lt 1) {
    throw "No $Kind discovery artifacts were saved in $Path"
  }

  $artifact = $artifacts[0].FullName
  $metadata = "$artifact.txt"

  Assert-Path $metadata "$Kind discovery metadata"
  Assert-TextContains $metadata "^kind\s*:\s*$Kind\s*$" "$Kind discovery metadata"
  Assert-TextContains $metadata "^source_seed\s*:" "$Kind discovery metadata"
  Assert-TextContains $metadata "^queue_entry\s*:" "$Kind discovery metadata"
  Assert-TextContains $metadata "^signal_hash\s*:" "$Kind discovery metadata"
  Assert-TextContains $metadata "^signal_len\s*:" "$Kind discovery metadata"

  if ($Kind -eq "coverage") {
    Assert-TextContains $metadata "^signal_detail\s*:\s*new_bits=\d+\s*$" "$Kind discovery metadata"
  }
}

function Assert-QueueManifest($Path) {
  Assert-Path $Path "queue manifest"
  Assert-TextContains $Path "^queue_id\tkind\tqueue_path\tsource_seed\tsignal_hash\tdetail$" "queue manifest"
  Assert-TextContains $Path "^\d+\tstate\t" "queue manifest"
  Assert-TextContains $Path "^\d+\tcoverage\t" "queue manifest"
}

function Assert-ExecLog($Path, $Outcome) {
  Assert-Path $Path "execution log"
  Assert-TextContains $Path "^exec_id\tseed_path\toutcome\tresponse_bytes\tresponse_states\tcoverage_bytes\tcoverage_new_bits\texit_code\ttarget_pid\tsend_failed\ttarget_timed_out\tcrash_reason\tactive_seeds\tunique_states\tunique_coverage\tsaved_crashes\tsaved_hangs\tsaved_net_errors$" "execution log"
  Assert-TextContains $Path "^\d+\t.*\t$Outcome\t" "execution log"
}

function Write-StaleExecLog($Path) {
  $staleHeader = "exec_id`tseed_path`toutcome`tresponse_bytes`tresponse_states`tcoverage_bytes`tcoverage_new_bits`texit_code`tsend_failed`ttarget_timed_out`tunique_states`tunique_coverage`tsaved_crashes`tsaved_hangs`tsaved_net_errors"
  Write-AsciiFile $Path "$staleHeader`r`n0`tstale.raw`told`t0`t0`t0`t0`t0x00000000`t0`t0`t0`t0`t0`t0`t0`r`n"
}

function Write-StaleQueueManifest($Path) {
  $staleHeader = "kind`tqueue_path`tsource_seed`tsignal_hash`tdetail"
  Write-AsciiFile $Path "$staleHeader`r`nstate`tqueue\stale.raw`tstale.raw`t00000000`told`r`n"
}

function Assert-RotatedOldSchema($Path, $Description) {
  Assert-Path "$Path.old-schema" "$Description old-schema rotation"
}

function Get-StatsValue($Path, $Name) {
  $pattern = "^\s*" + [regex]::Escape($Name) + "\s*:\s*(.+?)\s*$"

  foreach ($line in Get-Content -LiteralPath $Path) {
    if ($line -match $pattern) {
      return $Matches[1].Trim()
    }
  }

  throw "Missing stat '$Name' in $Path"
}

function Assert-StatsAtLeast($Path, $Name, [int]$Minimum) {
  $value = [int](Get-StatsValue $Path $Name)

  if ($value -lt $Minimum) {
    throw "Expected $Name >= $Minimum in $Path, got $value"
  }
}

function Assert-StatsEquals($Path, $Name, $Expected) {
  $value = Get-StatsValue $Path $Name

  if ($value -ne $Expected) {
    throw "Expected $Name = $Expected in $Path, got $value"
  }
}

function Remove-SafeDirectory($Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return }

  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Refusing to remove non-directory smoke output path: $Path"
  }

  $pathItem = Get-Item -LiteralPath $Path -Force
  if (($pathItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Refusing to remove reparse-point smoke output directory: $Path"
  }

  $repoRootClean = [System.IO.Path]::GetFullPath($RepoRoot).TrimEnd('\', '/')
  $pathRootClean = [System.IO.Path]::GetPathRoot($Path).TrimEnd('\', '/')
  $pathClean = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  $repoPrefix = $repoRootClean + [System.IO.Path]::DirectorySeparatorChar

  if ($pathClean -eq $repoRootClean -or $pathClean -eq $pathRootClean) {
    throw "Refusing to remove unsafe smoke output directory: $Path"
  }

  if (-not $pathClean.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove smoke output directory outside the repository: $Path"
  }

  Remove-Item -LiteralPath $Path -Recurse -Force
}

function Write-AsciiFile($Path, $Text) {
  $encoding = New-Object System.Text.ASCIIEncoding
  [System.IO.File]::WriteAllText($Path, $Text, $encoding)
}

function Assert-CleanRejectsFilePath($Path) {
  Write-AsciiFile $Path "not a directory`r`n"
  Assert-Throws { Remove-SafeDirectory $Path } "non-directory" "file-path clean refusal"
  Assert-Path $Path "file left untouched by clean refusal"
  Remove-Item -LiteralPath $Path -Force
}

function Invoke-Fuzzer([string[]]$Arguments, [string]$Label) {
  & $Fuzzer @Arguments

  if ($LASTEXITCODE -ne 0) {
    throw "$Label failed with exit code $LASTEXITCODE"
  }
}

function Test-TcpListenerReady([string]$Address, [int]$Port) {
  $targetAddress = [System.Net.IPAddress]::Parse($Address)
  $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()

  foreach ($listener in $listeners) {
    if ($listener.Port -ne $Port) {
      continue
    }

    if ($listener.Address.Equals($targetAddress) -or
        $listener.Address.Equals([System.Net.IPAddress]::Any) -or
        $listener.Address.Equals([System.Net.IPAddress]::IPv6Any)) {
      return $true
    }
  }

  return $false
}

function Wait-TcpListenerReady([string]$Address, [int]$Port, $Process, [int]$TimeoutMs) {
  $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)

  while ([DateTime]::UtcNow -lt $deadline) {
    if ($Process -and $Process.HasExited) {
      throw "external smoke server exited before listening on $Address`:$Port with code $($Process.ExitCode)"
    }

    if (Test-TcpListenerReady -Address $Address -Port $Port) {
      return
    }

    Start-Sleep -Milliseconds 25
  }

  throw "Timed out waiting for external smoke server to listen on $Address`:$Port"
}

function Invoke-NoLaunchFuzzer([string[]]$Arguments, [string]$Label) {
  if (Test-TcpListenerReady -Address "127.0.0.1" -Port $Port) {
    throw "Port $Port is already listening before $Label starts its external smoke server"
  }

  $serverProcess = Start-Process -FilePath $Server `
    -ArgumentList "$Port" `
    -WorkingDirectory $BuildDir `
    -PassThru `
    -WindowStyle Hidden

  Wait-TcpListenerReady -Address "127.0.0.1" -Port $Port -Process $serverProcess -TimeoutMs 5000

  try {
    Invoke-Fuzzer -Arguments $Arguments -Label $Label

    if (-not $serverProcess.WaitForExit(2000)) {
      Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
      throw "$Label external smoke server did not exit after the fuzzer disconnected"
    }

    if ($serverProcess.ExitCode -ne 0) {
      throw "$Label external smoke server exited with code $($serverProcess.ExitCode)"
    }
  } finally {
    if ($serverProcess -and -not $serverProcess.HasExited) {
      Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
      $null = $serverProcess.WaitForExit(1000)
    }
  }
}

$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$BuildDir = Resolve-RepoPath $BuildDir
$OutDir = Resolve-RepoPath $OutDir

$Fuzzer = Join-Path $BuildDir "aflnet-win-fuzz.exe"
$Server = Join-Path $BuildDir "aflnet-win-rtsp-smoke.exe"
$ServerName = "aflnet-win-rtsp-smoke.exe"

if (-not (Test-Path -LiteralPath $Fuzzer) -or
    -not (Test-Path -LiteralPath $Server)) {
  throw "Windows smoke binaries were not found. Build first with: powershell -ExecutionPolicy Bypass -File .\build-win.ps1"
}

Assert-Path $Fuzzer "Windows fuzzer binary"
Assert-Path $Server "RTSP smoke server binary"

if ($Clean) {
  Remove-SafeDirectory $OutDir
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Assert-CleanRejectsFilePath (Join-Path $OutDir "clean-refuses-file.tmp")

$SeedDir = Join-Path $OutDir "seeds"
$CrashSeedDir = Join-Path $OutDir "crash-seeds"
$ExitSeedDir = Join-Path $OutDir "exit-seeds"
$HangSeedDir = Join-Path $OutDir "hang-seeds"
$BasicOut = Join-Path $OutDir "basic"
$UdpOut = Join-Path $OutDir "udp"
$NoLaunchOut = Join-Path $OutDir "no-launch"
$DryRunOut = Join-Path $OutDir "dry-run"
$CrashOut = Join-Path $OutDir "crash"
$ExitCrashOut = Join-Path $OutDir "exit-crash"
$HangOut = Join-Path $OutDir "hang"
$CoveragePath = Join-Path $OutDir "coverage.bin"
$UdpCoveragePath = Join-Path $OutDir "coverage-udp.bin"
$EnvMarkerPath = Join-Path $OutDir "target-env-marker.txt"
$DictPath = Join-Path $RepoRoot "tutorials\live555\rtsp.dict"
$UdpPort = $Port + 1

New-Item -ItemType Directory -Force -Path $SeedDir | Out-Null
New-Item -ItemType Directory -Force -Path $CrashSeedDir | Out-Null
New-Item -ItemType Directory -Force -Path $ExitSeedDir | Out-Null
New-Item -ItemType Directory -Force -Path $HangSeedDir | Out-Null

$NormalSeed = (@"
OPTIONS rtsp://127.0.0.1:$Port/smoke RTSP/1.0
CSeq: 1

DESCRIBE rtsp://127.0.0.1:$Port/smoke RTSP/1.0
CSeq: 2

SETUP rtsp://127.0.0.1:$Port/smoke/track1 RTSP/1.0
CSeq: 3

PLAY rtsp://127.0.0.1:$Port/smoke RTSP/1.0
CSeq: 4

TEARDOWN rtsp://127.0.0.1:$Port/smoke RTSP/1.0
CSeq: 5

"@ -replace "`r?`n", "`r`n") + "`r`n"

$CrashSeed = (@"
OPTIONS rtsp://127.0.0.1:$Port/AFLNET_CRASH RTSP/1.0
CSeq: 1

"@ -replace "`r?`n", "`r`n") + "`r`n"

$HangSeed = (@"
OPTIONS rtsp://127.0.0.1:$Port/AFLNET_HANG RTSP/1.0
CSeq: 1

"@ -replace "`r?`n", "`r`n") + "`r`n"

$ExitSeed = (@"
OPTIONS rtsp://127.0.0.1:$Port/AFLNET_EXIT RTSP/1.0
CSeq: 1

"@ -replace "`r?`n", "`r`n") + "`r`n"

Write-AsciiFile (Join-Path $SeedDir "rtsp-seed.raw") $NormalSeed
Write-AsciiFile (Join-Path $CrashSeedDir "rtsp-crash.raw") $CrashSeed
Write-AsciiFile (Join-Path $ExitSeedDir "rtsp-exit.raw") $ExitSeed
Write-AsciiFile (Join-Path $HangSeedDir "rtsp-hang.raw") $HangSeed
New-Item -ItemType Directory -Force -Path $BasicOut | Out-Null
Write-StaleExecLog (Join-Path $BasicOut "exec_log.tsv")
Write-StaleQueueManifest (Join-Path $BasicOut "queue_manifest.tsv")

Invoke-Fuzzer -Arguments @(
  "-i", $SeedDir,
  "-o", $BasicOut,
  "-N", "tcp://127.0.0.1/$Port",
  "-P", "RTSP",
  "-B", $CoveragePath,
  "-C", $BuildDir,
  "-E", "AFLNET_SMOKE_ENV_MARKER=$EnvMarkerPath",
  "-X", $DictPath,
  "-D", "100000",
  "-W", "50",
  "-w", "10000",
  "-m", "0",
  "-x", "1",
  "--", $ServerName, "$Port"
) -Label "state and coverage smoke run"

Assert-Path (Join-Path $BasicOut "fuzzer_stats") "state smoke fuzzer_stats"
$BasicStats = Join-Path $BasicOut "fuzzer_stats"
Assert-StatsAtLeast $BasicStats "execs_done" 1
Assert-StatsAtLeast $BasicStats "active_seeds" 2
Assert-StatsAtLeast $BasicStats "unique_states" 1
Assert-StatsAtLeast $BasicStats "unique_coverage" 1
Assert-StatsAtLeast $BasicStats "coverage_bits_seen" 1
Assert-StatsAtLeast $BasicStats "coverage_map_bytes" 1
Assert-StatsAtLeast $BasicStats "dictionary_tokens" 1
Assert-StatsEquals $BasicStats "target_env_vars" 1
Assert-TextContains $BasicStats "^target_command\s*:.*aflnet-win-rtsp-smoke\.exe" "state smoke fuzzer_stats"
Assert-TextContains $BasicStats "^target_env_000\s*:\s*AFLNET_SMOKE_ENV_MARKER=" "state smoke fuzzer_stats"
Assert-StatsEquals $BasicStats "stop_reason" "iteration_limit"
Assert-TextContains $BasicStats "^exec_log\s*:" "state smoke fuzzer_stats"
Assert-Path $EnvMarkerPath "target environment marker"
Assert-Path (Join-Path $BasicOut "coverage_bits.bin") "persisted coverage bitmap discovery state"
Assert-Path (Join-Path $BasicOut "coverage_hashes.txt") "coverage hash index"
Assert-RotatedOldSchema (Join-Path $BasicOut "exec_log.tsv") "stale execution log"
Assert-RotatedOldSchema (Join-Path $BasicOut "queue_manifest.tsv") "stale queue manifest"
Assert-DiscoveryMetadata (Join-Path $BasicOut "states") "state"
Assert-DiscoveryMetadata (Join-Path $BasicOut "coverage") "coverage"
Assert-QueueManifest (Join-Path $BasicOut "queue_manifest.tsv")
Assert-ExecLog (Join-Path $BasicOut "exec_log.tsv") "ok"

Invoke-Fuzzer -Arguments @(
  "-i", $SeedDir,
  "-o", $UdpOut,
  "-N", "udp://127.0.0.1/$UdpPort",
  "-P", "RTSP",
  "-B", $UdpCoveragePath,
  "-C", $BuildDir,
  "-D", "100000",
  "-W", "50",
  "-w", "10000",
  "-m", "0",
  "-x", "1",
  "--", $ServerName, "$UdpPort", "udp"
) -Label "udp state and coverage smoke run"

Assert-Path (Join-Path $UdpOut "fuzzer_stats") "udp smoke fuzzer_stats"
$UdpStats = Join-Path $UdpOut "fuzzer_stats"
Assert-StatsAtLeast $UdpStats "execs_done" 1
Assert-StatsAtLeast $UdpStats "active_seeds" 2
Assert-StatsAtLeast $UdpStats "unique_states" 1
Assert-StatsAtLeast $UdpStats "unique_coverage" 1
Assert-StatsAtLeast $UdpStats "coverage_bits_seen" 1
Assert-StatsAtLeast $UdpStats "coverage_map_bytes" 1
Assert-StatsEquals $UdpStats "stop_reason" "iteration_limit"
Assert-Path (Join-Path $UdpOut "coverage_bits.bin") "udp persisted coverage bitmap discovery state"
Assert-Path (Join-Path $UdpOut "coverage_hashes.txt") "udp coverage hash index"
Assert-DiscoveryMetadata (Join-Path $UdpOut "states") "state"
Assert-DiscoveryMetadata (Join-Path $UdpOut "coverage") "coverage"
Assert-QueueManifest (Join-Path $UdpOut "queue_manifest.tsv")
Assert-ExecLog (Join-Path $UdpOut "exec_log.tsv") "ok"

Invoke-NoLaunchFuzzer -Arguments @(
  "-i", $SeedDir,
  "-o", $NoLaunchOut,
  "-N", "tcp://127.0.0.1/$Port",
  "-P", "RTSP",
  "-W", "50",
  "-w", "10000",
  "-m", "0",
  "-x", "1",
  "--no-launch"
) -Label "no-launch smoke run"

Assert-Path (Join-Path $NoLaunchOut "fuzzer_stats") "no-launch smoke fuzzer_stats"
$NoLaunchStats = Join-Path $NoLaunchOut "fuzzer_stats"
Assert-StatsAtLeast $NoLaunchStats "execs_done" 1
Assert-StatsAtLeast $NoLaunchStats "active_seeds" 2
Assert-StatsAtLeast $NoLaunchStats "unique_states" 1
Assert-StatsEquals $NoLaunchStats "no_launch" 1
Assert-StatsEquals $NoLaunchStats "target_path" "external"
Assert-StatsEquals $NoLaunchStats "target_command" "external"
Assert-StatsEquals $NoLaunchStats "stop_reason" "iteration_limit"
Assert-DiscoveryMetadata (Join-Path $NoLaunchOut "states") "state"
Assert-ExecLog (Join-Path $NoLaunchOut "exec_log.tsv") "ok"

Invoke-Fuzzer -Arguments @(
  "-i", $SeedDir,
  "-o", $DryRunOut,
  "-N", "tcp://127.0.0.1/$Port",
  "-P", "RTSP",
  "-C", $BuildDir,
  "-D", "100000",
  "-W", "50",
  "-w", "10000",
  "-Z",
  "--", $ServerName, "$Port"
) -Label "dry-run smoke pass"

Assert-Path (Join-Path $DryRunOut "fuzzer_stats") "dry-run smoke fuzzer_stats"
$DryRunStats = Join-Path $DryRunOut "fuzzer_stats"
Assert-StatsAtLeast $DryRunStats "execs_done" 1
Assert-StatsEquals $DryRunStats "dry_run" 1
Assert-StatsEquals $DryRunStats "stop_reason" "dry_run"
Assert-ExecLog (Join-Path $DryRunOut "exec_log.tsv") "dry_run"

$CrashArgs = @(
  "-i", $CrashSeedDir,
  "-o", $CrashOut,
  "-N", "tcp://127.0.0.1/$Port",
  "-P", "RTSP",
  "-C", $BuildDir,
  "-D", "100000",
  "-W", "50",
  "-w", "10000",
  "-m", "0",
  "-x", "1",
  "-E", "AFLNET_SMOKE_CRASH_ENV=1",
  "--minidump",
  "--", $ServerName, "$Port"
)

Invoke-Fuzzer -Arguments $CrashArgs -Label "crash smoke run"

Assert-Path (Join-Path $CrashOut "fuzzer_stats") "crash smoke fuzzer_stats"
$CrashStats = Join-Path $CrashOut "fuzzer_stats"
Assert-StatsAtLeast $CrashStats "execs_done" 1
Assert-StatsAtLeast $CrashStats "saved_crashes" 1
Assert-StatsEquals $CrashStats "minidump" 1
Assert-StatsEquals $CrashStats "target_env_vars" 1
Assert-StatsEquals $CrashStats "stop_reason" "iteration_limit"
Assert-TextContains $CrashStats "^exec_log\s*:" "crash smoke fuzzer_stats"
Assert-Path (Join-Path $CrashOut "crash_hashes.txt") "crash hash index"
Assert-CrashArtifactSet (Join-Path $CrashOut "replayable-crashes") -ExpectMinidump -ExpectedEnv "AFLNET_SMOKE_CRASH_ENV=1" -ExpectedReason "exception_status"
Assert-ExecLog (Join-Path $CrashOut "exec_log.tsv") "crash"
$SavedCrashesBeforeResume = [int](Get-StatsValue $CrashStats "saved_crashes")

Invoke-Fuzzer -Arguments $CrashArgs -Label "crash resume counter smoke run"
Assert-StatsEquals $CrashStats "saved_crashes" $SavedCrashesBeforeResume

Invoke-Fuzzer -Arguments @(
  "-i", $ExitSeedDir,
  "-o", $ExitCrashOut,
  "-N", "tcp://127.0.0.1/$Port",
  "-P", "RTSP",
  "-C", $BuildDir,
  "-D", "100000",
  "-W", "50",
  "-w", "10000",
  "-m", "0",
  "-x", "1",
  "--crash-on-exit",
  "--", $ServerName, "$Port"
) -Label "nonzero-exit crash smoke run"

Assert-Path (Join-Path $ExitCrashOut "fuzzer_stats") "nonzero-exit crash smoke fuzzer_stats"
$ExitCrashStats = Join-Path $ExitCrashOut "fuzzer_stats"
Assert-StatsAtLeast $ExitCrashStats "execs_done" 1
Assert-StatsAtLeast $ExitCrashStats "saved_crashes" 1
Assert-StatsEquals $ExitCrashStats "crash_on_exit" 1
Assert-StatsEquals $ExitCrashStats "stop_reason" "iteration_limit"
Assert-Path (Join-Path $ExitCrashOut "crash_hashes.txt") "nonzero-exit crash hash index"
Assert-CrashArtifactSet (Join-Path $ExitCrashOut "replayable-crashes") -ExpectedReason "nonzero_exit"
Assert-ExecLog (Join-Path $ExitCrashOut "exec_log.tsv") "crash"

Invoke-Fuzzer -Arguments @(
  "-i", $HangSeedDir,
  "-o", $HangOut,
  "-N", "tcp://127.0.0.1/$Port",
  "-P", "RTSP",
  "-C", $BuildDir,
  "-D", "100000",
  "-W", "50",
  "-w", "10000",
  "-t", "100",
  "-m", "0",
  "-x", "1",
  "--", $ServerName, "$Port"
) -Label "hang smoke run"

Assert-Path (Join-Path $HangOut "fuzzer_stats") "hang smoke fuzzer_stats"
$HangStats = Join-Path $HangOut "fuzzer_stats"
Assert-StatsAtLeast $HangStats "execs_done" 1
Assert-StatsAtLeast $HangStats "saved_hangs" 1
Assert-StatsEquals $HangStats "stop_reason" "iteration_limit"
Assert-TextContains $HangStats "^exec_log\s*:" "hang smoke fuzzer_stats"
Assert-Path (Join-Path $HangOut "hang_hashes.txt") "hang hash index"
Assert-HangArtifactSet (Join-Path $HangOut "hangs")
Assert-ExecLog (Join-Path $HangOut "exec_log.tsv") "hang"

Write-Host "Windows smoke verification passed."
Write-Host "State output: $BasicOut"
Write-Host "UDP output: $UdpOut"
Write-Host "No-launch output: $NoLaunchOut"
Write-Host "Dry-run output: $DryRunOut"
Write-Host "Crash output: $CrashOut"
Write-Host "Nonzero-exit crash output: $ExitCrashOut"
Write-Host "Hang output: $HangOut"
