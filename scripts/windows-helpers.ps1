# Shared by install.ps1 and run.ps1 (dot-sourced after they Set-Location to the repository).

# Docker Desktop can be installed and running while docker.exe is not on this session's PATH
# (a terminal opened before the install, or a per-user install). Add its folder for this run.
function Add-DockerToSessionPath {
    if (Get-Command docker -ErrorAction SilentlyContinue) { return }
    $dirs = @()
    if ($env:ProgramFiles) { $dirs += (Join-Path (Join-Path (Join-Path (Join-Path $env:ProgramFiles "Docker") "Docker") "resources") "bin") }
    if ($env:ProgramData) { $dirs += (Join-Path (Join-Path $env:ProgramData "DockerDesktop") "version-bin") }
    if ($env:LOCALAPPDATA) { $dirs += (Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $env:LOCALAPPDATA "Programs") "Docker") "Docker") "resources") "bin") }
    if ($env:USERPROFILE) { $dirs += (Join-Path (Join-Path $env:USERPROFILE ".docker") "bin") }
    foreach ($dir in $dirs) {
        if ((Test-Path -LiteralPath (Join-Path $dir "docker.exe")) -or (Test-Path -LiteralPath (Join-Path $dir "docker"))) {
            $env:PATH = $dir + [IO.Path]::PathSeparator + $env:PATH
            Write-Host "  [note]    docker was not on PATH; using $dir for this run."
            Write-Host "            If later commands cannot find docker, open a new terminal or add that folder to PATH."
            return
        }
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
