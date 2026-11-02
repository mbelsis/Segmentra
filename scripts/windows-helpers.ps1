# Shared by install.ps1 and run.ps1 (dot-sourced after they Set-Location to the repository).

# Programs installed after this terminal was opened are not on its PATH until it is re-read.
function Update-SessionPath {
    $parts = @(
        [Environment]::GetEnvironmentVariable("Path", "Machine"),
        [Environment]::GetEnvironmentVariable("Path", "User"),
        $env:PATH
    ) | Where-Object { $_ }
    $env:PATH = $parts -join [IO.Path]::PathSeparator
}

# Where Docker Desktop is installed differs per machine (per-user installs, custom folders), so
# this looks instead of assuming: folders with "docker" in their name in the usual install
# locations, and the install location Windows recorded for its uninstaller.
function Get-DockerInstallDirs {
    $dirs = @()
    $roots = @($env:ProgramW6432, $env:ProgramFiles, $env:ProgramData)
    if ($env:LOCALAPPDATA) { $roots += (Join-Path $env:LOCALAPPDATA "Programs") }
    foreach ($root in ($roots | Where-Object { $_ } | Select-Object -Unique)) {
        $dirs += @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'docker' } | ForEach-Object { $_.FullName })
    }
    foreach ($key in "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop",
                     "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop") {
        $location = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).InstallLocation
        if ($location -and (Test-Path -LiteralPath $location)) { $dirs += $location }
    }
    return @($dirs | Select-Object -Unique)
}

function Find-InDockerInstallDirs([string]$fileName) {
    foreach ($dir in (Get-DockerInstallDirs)) {
        $found = Get-ChildItem -LiteralPath $dir -Filter $fileName -File -Recurse -Depth 4 -ErrorAction SilentlyContinue |
            Sort-Object { if ($_.FullName -match 'resources') { 0 } else { 1 } } |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

# Docker Desktop can be running while docker.exe is not on this session's PATH.
function Add-DockerToSessionPath {
    if (Get-Command docker -ErrorAction SilentlyContinue) { return }
    Update-SessionPath
    if (Get-Command docker -ErrorAction SilentlyContinue) { return }

    $exeName = if ($env:OS -eq "Windows_NT") { "docker.exe" } else { "docker" }
    $exe = Find-InDockerInstallDirs $exeName
    $binDir = if ($exe) { Split-Path $exe -Parent } else { $null }
    # Not found yet: a running Docker Desktop knows where it is. Look around its executable.
    if (-not $binDir) {
        $running = Get-Process -Name "Docker Desktop", "com.docker.backend" -ErrorAction SilentlyContinue |
            Where-Object { $_.Path } | ForEach-Object { Split-Path $_.Path -Parent } | Select-Object -Unique
        foreach ($start in $running) {
            $dir = $start
            for ($up = 0; $up -lt 4 -and $dir -and -not $binDir; $up++) {
                foreach ($candidate in (Join-Path $dir "bin"), (Join-Path (Join-Path $dir "resources") "bin")) {
                    if (Test-Path -LiteralPath (Join-Path $candidate $exeName)) { $binDir = $candidate; break }
                }
                $dir = Split-Path $dir -Parent
            }
            if ($binDir) { break }
        }
    }
    if (-not $binDir -and $env:USERPROFILE) {
        $userBin = Join-Path (Join-Path $env:USERPROFILE ".docker") "bin"
        if (Test-Path -LiteralPath (Join-Path $userBin $exeName)) { $binDir = $userBin }
    }
    if ($binDir) {
        $env:PATH = $binDir + [IO.Path]::PathSeparator + $env:PATH
        Write-Host "  [note]    docker was not on PATH; using $binDir for this run."
        Write-Host "            If docker commands fail in this terminal, add that folder to PATH."
    }
}

function Write-DockerMissing {
    if (Test-DockerDesktopProcess) {
        Write-Host "  [blocked] Docker Desktop is running, but the docker command could not be found"
        Write-Host "            Find it with:  Get-ChildItem `"<Docker Desktop folder>`" -Recurse -Filter docker.exe"
        Write-Host "            Then add its folder for this window:  `$env:PATH = `"<that folder>;`$env:PATH`""
    } else {
        Write-Host "  [missing] Docker"
        Write-Host "            Install Docker Desktop: https://docs.docker.com/desktop/setup/install/windows-install/"
        Write-Host "            If Docker only runs inside WSL, run ./install.sh there instead."
    }
}

function Test-DockerDesktopProcess {
    return [bool](Get-Process -Name "Docker Desktop", "com.docker.backend" -ErrorAction SilentlyContinue)
}

# Returns ok | missing | denied | starting | stopped | windows, and sets $script:DockerError
# to what docker itself said, so failures can show the real reason.
$script:DockerError = ""
function Get-DockerState {
    $script:DockerError = ""
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { return "missing" }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    # --format: only the server's OS, so client warnings cannot be taken for the failure.
    try { $out = (& docker version --format '{{.Server.Os}}' 2>&1 | Out-String); $code = $LASTEXITCODE }
    catch { $out = "$_"; $code = 1 }
    finally { $ErrorActionPreference = $prevEap }
    if ($code -eq 0) {
        if ($out -match '(?m)^\s*windows\s*$') { return "windows" }
        return "ok"
    }
    $script:DockerError = (($out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 3) -join " ").Trim()
    if ($out -match 'permission denied|access is denied') { return "denied" }
    if (Test-DockerDesktopProcess) { return "starting" }
    return "stopped"
}

function Write-DockerError {
    if ($script:DockerError) { Write-Host "            Docker says: $($script:DockerError)" }
}

function Write-WindowsContainersHint {
    Write-Host "            Segmentra needs Linux containers. Right-click the Docker icon in the taskbar"
    Write-Host "            and choose 'Switch to Linux containers...', then run this again."
}

# A value the way docker compose resolves it: environment, then .env, then the default.
function Get-EnvValue([string]$key, [string]$default) {
    $value = [Environment]::GetEnvironmentVariable($key)
    if (-not $value -and (Test-Path -LiteralPath ".env")) {
        foreach ($line in (Get-Content -LiteralPath ".env")) {
            if ($line -match "^$key=(.*)$") { $value = $Matches[1].Trim().Trim('"', "'") }
        }
    }
    if ($value) { return $value }
    return $default
}

# The project name docker compose really uses: it strips characters from the folder name
# ("Segmentra-main (1)" becomes "segmentra-main1") and honours COMPOSE_PROJECT_NAME in .env.
function Get-ComposeProject {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $config = & docker compose config 2>$null } catch { $config = @() }
    finally { $ErrorActionPreference = $prevEap }
    foreach ($line in @($config)) {
        if ("$line" -match '^name:\s*(\S+)\s*$') { return $Matches[1] }
    }
    return ((Split-Path (Get-Location).Path -Leaf).ToLower() -replace '[^-_a-z0-9]', '') -replace '^[-_]+', ''
}
