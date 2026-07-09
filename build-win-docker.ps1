param(
  [string]$BuildDir = "build-win",
  [string]$Image = "aflnet/windows-cross:latest",
  [switch]$Clean,
  [switch]$SkipImageBuild
)

$ErrorActionPreference = "Stop"

function Resolve-RepoRelativeBuildDir($Path) {
  if ([System.IO.Path]::IsPathRooted($Path)) {
    throw "BuildDir must be relative to the repository when using Docker: $Path"
  }

  $normalized = $Path -replace '\\', '/'
  $parts = @($normalized -split '/' | Where-Object { $_ -and $_ -ne "." })

  foreach ($part in $parts) {
    if ($part -eq "..") {
      throw "BuildDir must stay inside the repository: $Path"
    }
  }

  if (-not $parts.Count) {
    throw "BuildDir cannot be empty"
  }

  return ($parts -join '/')
}

function Remove-SafeBuildDir($Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return }

  $repoRootClean = [System.IO.Path]::GetFullPath($RepoRoot).TrimEnd('\', '/')
  $pathRootClean = [System.IO.Path]::GetPathRoot($Path).TrimEnd('\', '/')
  $pathClean = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  $repoPrefix = $repoRootClean + [System.IO.Path]::DirectorySeparatorChar

  if ($pathClean -eq $repoRootClean -or $pathClean -eq $pathRootClean) {
    throw "Refusing to clean unsafe build directory: $Path"
  }

  if (-not $pathClean.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean build directory outside the repository: $Path"
  }

  Remove-Item -LiteralPath $Path -Recurse -Force
}

$RepoRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$Dockerfile = Join-Path $RepoRoot "docker\windows-cross.Dockerfile"
$ContainerBuildDir = Resolve-RepoRelativeBuildDir $BuildDir
$HostBuildDir = Join-Path $RepoRoot ($ContainerBuildDir -replace '/', [System.IO.Path]::DirectorySeparatorChar)

$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
  throw "Docker was not found. Start Docker Desktop and make sure docker.exe is on PATH."
}

if ($Clean) {
  Remove-SafeBuildDir $HostBuildDir
}

if (-not $SkipImageBuild) {
  & $docker.Source build `
    -f $Dockerfile `
    -t $Image `
    $RepoRoot

  if ($LASTEXITCODE -ne 0) {
    throw "Docker toolchain image build failed with exit code $LASTEXITCODE"
  }
}

$mount = "type=bind,source=$RepoRoot,target=/src"
$buildPath = "/src/$ContainerBuildDir"
$buildCommand = "cmake -S /src -B $buildPath -G Ninja -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc && cmake --build $buildPath --parallel"

& $docker.Source run `
  --rm `
  --mount $mount `
  -w /src `
  $Image `
  sh -lc $buildCommand

if ($LASTEXITCODE -ne 0) {
  throw "Docker Windows cross-build failed with exit code $LASTEXITCODE"
}

Write-Host "Built Windows tools in $HostBuildDir"
Write-Host "Expected binaries: afl-replay.exe, aflnet-replay.exe, aflnet-win-fuzz.exe, aflnet-win-rtsp-smoke.exe"
Write-Host "Expected library: libaflnet-win-sancov.a"
