param(
  [string]$BuildDir = "build-win",
  [ValidateSet("auto", "ninja", "mingw")]
  [string]$Generator = "auto",
  [switch]$Clean
)

$ErrorActionPreference = "Stop"

function Add-ToolPath($Path) {
  if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Container)) {
    return
  }

  try {
    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  } catch {
    return
  }

  $entries = @($env:PATH -split ';' | Where-Object { $_ })

  foreach ($entry in $entries) {
    try {
      $entryPath = [System.IO.Path]::GetFullPath($entry).TrimEnd('\', '/')
    } catch {
      continue
    }

    if ($entryPath -eq $fullPath) {
      return
    }
  }

  $env:PATH = $fullPath + ';' + $env:PATH
}

function Add-KnownToolchainPaths {
  $candidates = @()

  if ($env:MSYS2_ROOT) {
    $candidates += @(
      "$env:MSYS2_ROOT\ucrt64\bin",
      "$env:MSYS2_ROOT\mingw64\bin",
      "$env:MSYS2_ROOT\clang64\bin",
      "$env:MSYS2_ROOT\mingw32\bin",
      "$env:MSYS2_ROOT\clangarm64\bin",
      "$env:MSYS2_ROOT\usr\bin"
    )
  }

  $candidates += @(
    "C:\msys64\ucrt64\bin",
    "C:\msys64\mingw64\bin",
    "C:\msys64\clang64\bin",
    "C:\msys64\mingw32\bin",
    "C:\msys64\clangarm64\bin",
    "C:\msys64\usr\bin",
    "C:\Program Files\LLVM\bin",
    "$env:LOCALAPPDATA\Programs\LLVM\bin",
    "C:\Program Files\CMake\bin",
    "C:\Program Files\Ninja",
    "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Ninja-build.Ninja_Microsoft.Winget.Source_8wekyb3d8bbwe",
    "C:\ProgramData\chocolatey\bin",
    "$env:USERPROFILE\scoop\shims"
  )

  foreach ($candidate in $candidates) {
    Add-ToolPath $candidate
  }
}

function Find-Command($Name) {
  return Get-Command $Name -ErrorAction SilentlyContinue
}

function Resolve-Tool($NameOrPath) {
  $command = Find-Command $NameOrPath
  if ($command) {
    return $command.Source
  }

  if (Test-Path -LiteralPath $NameOrPath -PathType Leaf) {
    return [System.IO.Path]::GetFullPath($NameOrPath)
  }

  return $null
}

Add-KnownToolchainPaths

$cmake = Find-Command "cmake"
if (-not $cmake) {
  throw "CMake was not found. Install CMake or add it to PATH before building the Windows tools."
}

if (-not $env:CC) {
  $gcc = Find-Command "gcc"
  $clang = Find-Command "clang"

  if (-not $gcc -and -not $clang) {
    throw "No GNU-like C compiler was found. Install MSYS2 MinGW-w64 GCC or LLVM clang, set CC to a compiler path, or add its bin directory to PATH. Checked PATH plus common MSYS2/LLVM locations. MSVC is not supported for these AFL sources yet."
  }

  if ($gcc) {
    $env:CC = $gcc.Source
  } else {
    $env:CC = $clang.Source
  }
} else {
  $resolvedCc = Resolve-Tool $env:CC
  if (-not $resolvedCc) {
    throw "CC is set to '$env:CC', but that compiler was not found. Set CC to a GNU-like compiler path, or clear CC and let build-win.ps1 auto-detect MSYS2 GCC or LLVM clang."
  }
  $env:CC = $resolvedCc
}

$ninja = Find-Command "ninja"
$mingwMake = Find-Command "mingw32-make"

switch ($Generator) {
  "ninja" {
    if (-not $ninja) { throw "Generator 'ninja' requested, but ninja was not found. Checked PATH plus common Ninja install locations." }
    $cmakeGenerator = "Ninja"
  }
  "mingw" {
    if (-not $mingwMake) { throw "Generator 'mingw' requested, but mingw32-make was not found. Checked PATH plus common MSYS2 install locations." }
    $cmakeGenerator = "MinGW Makefiles"
  }
  default {
    if ($ninja) {
      $cmakeGenerator = "Ninja"
    } elseif ($mingwMake) {
      $cmakeGenerator = "MinGW Makefiles"
    } else {
      throw "Neither ninja nor mingw32-make was found. Install Ninja or MSYS2 MinGW Makefiles support, or add the build tool to PATH."
    }
  }
}

Write-Host "Windows build toolchain:"
Write-Host "  CMake     : $($cmake.Source)"
Write-Host "  Compiler  : $env:CC"
Write-Host "  Generator : $cmakeGenerator"
if ($ninja) { Write-Host "  Ninja     : $($ninja.Source)" }
if ($mingwMake) { Write-Host "  MinGW make: $($mingwMake.Source)" }

if ([System.IO.Path]::IsPathRooted($BuildDir)) {
  $resolvedBuildDir = $BuildDir
} else {
  $resolvedBuildDir = Join-Path $PSScriptRoot $BuildDir
}

$resolvedBuildDir = [System.IO.Path]::GetFullPath($resolvedBuildDir)

if ($Clean -and (Test-Path -LiteralPath $resolvedBuildDir)) {
  $repoRoot = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\', '/')
  $buildRoot = [System.IO.Path]::GetPathRoot($resolvedBuildDir).TrimEnd('\', '/')
  $safeBuildDir = $resolvedBuildDir.TrimEnd('\', '/')
  $repoPrefix = $repoRoot + [System.IO.Path]::DirectorySeparatorChar

  if ($safeBuildDir -eq $repoRoot -or $safeBuildDir -eq $buildRoot) {
    throw "Refusing to clean unsafe build directory: $resolvedBuildDir"
  }

  if (-not $safeBuildDir.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean build directory outside the repository: $resolvedBuildDir"
  }

  Remove-Item -LiteralPath $resolvedBuildDir -Recurse -Force
}

& $cmake.Source -S $PSScriptRoot -B $resolvedBuildDir -G $cmakeGenerator
& $cmake.Source --build $resolvedBuildDir --parallel

Write-Host "Built Windows tools in $resolvedBuildDir"
Write-Host "Expected binaries: afl-replay.exe, aflnet-replay.exe, aflnet-win-fuzz.exe, aflnet-win-rtsp-smoke.exe"
Write-Host "Expected library: aflnet-win-sancov static library for clang SanitizerCoverage targets"
