# No param() block on purpose: the options are read from $args. A declared parameter with
# [Parameter()] makes this an advanced script, and PowerShell then claims -d for -Debug and
# rejects -p as ambiguous (-ProgressAction, -PipelineVariable) before any of this code runs.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$Mode = $null
$AssumeYes = $false
$CheckOnly = $false
$badArgs = $false
foreach ($a in $args) {
    $opt = "$a"
    $wanted = $null
    if ($opt -match '^-{0,2}(d|dev|development)$') { $wanted = "development" }
    elseif ($opt -match '^-{0,2}(p|prod|production)$') { $wanted = "production" }
    elseif ($opt -match '^-{1,2}(y|yes)$') { $AssumeYes = $true }
    elseif ($opt -match '^-{1,2}check$') { $CheckOnly = $true }
    else { $badArgs = $true }
    if ($wanted) {
        if ($Mode -and $Mode -ne $wanted) { $badArgs = $true }
        $Mode = $wanted
    }
}
if (-not $Mode) { $Mode = "development" }
if ($badArgs) {
    Write-Host "Usage: .\install.ps1 [--development | --production] [--yes] [--check]"
    Write-Host ""
    Write-Host "  --development, --dev, -d   Local dev: Node.js + PostgreSQL in Docker (default)"
    Write-Host "  --production, --prod, -p   Everything in Docker, secrets generated into .env"
    Write-Host "  --yes, -y                  Accept every offer to start Docker or install a missing prerequisite"
    Write-Host "  --check                    Only report the prerequisites for the chosen mode; change nothing"
    exit 1
}

Write-Host "========================================"
Write-Host " Segmentra Installer ($Mode)"
Write-Host "========================================"
Write-Host ""

# Run a native command and only look at its exit code. With $ErrorActionPreference = "Stop",
# Windows PowerShell 5.1 turns any redirected stderr line (e.g. a docker warning) into a
# terminating error, while PowerShell 7 never does; checking $LASTEXITCODE works in both.
function Test-NativeSuccess([scriptblock]$block) {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $block 2>&1 | Out-Null; return ($LASTEXITCODE -eq 0) }
    catch { return $false }
    finally { $ErrorActionPreference = $prevEap }
}
function Invoke-Checked([string]$what, [scriptblock]$block) {
    & $block
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" }
}

# Prerequisites: report everything first, then fix what can be fixed, asking before each change.
# Docker itself is never installed from here (licensing, admin rights, reboots), only started.
function Confirm-Step([string]$question) {
    if ($AssumeYes) { Write-Host "  $question [Y/n] y (--yes)"; return $true }
    if ([Console]::IsInputRedirected) { Write-Host "  $question Skipped: no terminal to ask on (use --yes to accept)."; return $false }
    $reply = Read-Host "  $question [Y/n]"
    return ($reply -eq "" -or $reply -match '^[Yy]')
}

function Get-DockerState {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { return "missing" }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $out = (& docker info 2>&1 | Out-String); $code = $LASTEXITCODE }
    catch { $out = "$_"; $code = 1 }
    finally { $ErrorActionPreference = $prevEap }
    if ($code -eq 0) { return "ok" }
    if ($out -match 'permission denied|access is denied') { return "denied" }
    return "stopped"
}

function Get-NodeMajor {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { return 0 }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $version = "$(& node -v 2>$null)" } catch { $version = "" } finally { $ErrorActionPreference = $prevEap }
    if ($version -match '^v?(\d+)\.') { return [int]$Matches[1] }
    return 0
}
function Test-NodeOk {
    return ((Get-NodeMajor) -ge 20) -and [bool](Get-Command npm -ErrorAction SilentlyContinue)
}

# Programs installed by winget are not on this session's PATH until it is re-read.
function Update-SessionPath {
    $parts = @(
        [Environment]::GetEnvironmentVariable("Path", "Machine"),
        [Environment]::GetEnvironmentVariable("Path", "User"),
        $env:Path
    ) | Where-Object { $_ }
    $env:Path = $parts -join [IO.Path]::PathSeparator
}

function Install-NodeWithWinget {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "  winget is not available on this machine."
        return
    }
    if (-not (Confirm-Step "Install Node.js LTS with winget? (Windows may ask for administrator approval)")) { return }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    # The exit code is not used: winget also fails for "already installed". Test-NodeOk decides.
    try { & winget install --exact --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements | Out-Host }
    catch { Write-Host "  winget failed: $_" }
    finally { $ErrorActionPreference = $prevEap }
    Update-SessionPath
}

function Start-DockerDesktop {
    if ($env:DOCKER_HOST) {
        Write-Host "  ERROR: the Docker daemon at DOCKER_HOST=$($env:DOCKER_HOST) is not reachable." -ForegroundColor Red
        return $false
    }
    if (-not (Confirm-Step "Docker is not running. Start Docker Desktop?")) { return $false }
    $roots = @()
    if ($env:ProgramFiles) { $roots += $env:ProgramFiles }
    if ($env:LOCALAPPDATA) { $roots += (Join-Path $env:LOCALAPPDATA "Programs") }
    $exe = $roots |
        ForEach-Object { Join-Path (Join-Path (Join-Path $_ "Docker") "Docker") "Docker Desktop.exe" } |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1
    if (-not $exe) {
        Write-Host "  ERROR: could not find Docker Desktop. Start it yourself." -ForegroundColor Red
        return $false
    }
    Start-Process -FilePath $exe | Out-Null
    Write-Host "  Waiting for Docker (up to 2 minutes)..."
    for ($i = 0; $i -lt 60; $i++) {
        if ((Get-DockerState) -eq "ok") { return $true }
        Start-Sleep -Seconds 2
    }
    Write-Host "  ERROR: Docker did not become ready in time." -ForegroundColor Red
    return $false
}

function Invoke-PrerequisiteCheck {
    $failed = $false
    $blocked = $false
    $dockerHint = "            Install Docker Desktop: https://docs.docker.com/desktop/setup/install/windows-install/"
    $state = Get-DockerState
    switch ($state) {
        "ok"      { Write-Host "  [ok]      Docker is running" }
        "stopped" { Write-Host "  [stopped] Docker is installed but not running"; $failed = $true }
        "denied"  {
            Write-Host "  [blocked] Docker is running but this user may not use it"
            Write-Host "            Add the user to the docker-users group, then sign out and in again."
            $blocked = $true; $failed = $true
        }
        "missing" {
            Write-Host "  [missing] Docker"
            Write-Host $dockerHint
            $blocked = $true; $failed = $true
        }
    }
    if ($state -ne "missing") {
        if (Test-NativeSuccess { docker compose version }) {
            Write-Host "  [ok]      Docker Compose"
        } else {
            Write-Host "  [missing] Docker Compose plugin"
            Write-Host $dockerHint
            $blocked = $true; $failed = $true
        }
    }

    $nodeOk = $true
    if ($Mode -eq "development") {
        $nodeOk = Test-NodeOk
        if ($nodeOk) {
            Write-Host "  [ok]      Node.js $(node -v), npm"
        } else {
            $failed = $true
            if (Get-Command node -ErrorAction SilentlyContinue) {
                Write-Host "  [old]     Node.js 20+ and npm are required. Found: $(node -v)"
            } else {
                Write-Host "  [missing] Node.js 20+"
            }
        }
        foreach ($tool in "ssh", "sshpass") {
            if (Get-Command $tool -ErrorAction SilentlyContinue) { Write-Host "  [ok]      $tool" }
            else { Write-Host "  [note]    $tool not found (optional)" }
        }
    }

    if ($CheckOnly) {
        Write-Host ""
        if ($failed) { Write-Host "Some prerequisites are missing."; exit 1 }
        Write-Host "All required prerequisites are in place."
        exit 0
    }

    # Stop before changing anything if a problem cannot be fixed from here.
    if ($blocked) {
        Write-Host ""
        Write-Host "ERROR: fix the problems above and run the installer again. Nothing was changed." -ForegroundColor Red
        exit 1
    }

    if ($state -eq "stopped" -and -not (Start-DockerDesktop)) {
        Write-Host "ERROR: Docker is not running. Start Docker Desktop and run the installer again." -ForegroundColor Red
        exit 1
    }

    if (-not $nodeOk) {
        Install-NodeWithWinget
        if (-not (Test-NodeOk)) {
            Write-Host "ERROR: Node.js 20+ and npm are required. Install them from https://nodejs.org and run the installer again." -ForegroundColor Red
            exit 1
        }
        Write-Host "  Node.js $(node -v) OK"
    }

    # Development only: the SSH executor runs on this machine. Not installed from here because
    # sshpass has no official Windows package; production mode has it in the API image.
    if ($Mode -eq "development" -and -not (Get-Command sshpass -ErrorAction SilentlyContinue)) {
        Write-Host "  WARNING: sshpass is missing, so password-based SSH credentials will not work in development mode." -ForegroundColor Yellow
        Write-Host "           SSH keys may still work. To deploy from Windows, .\install.ps1 --production is the safer choice." -ForegroundColor Yellow
    }
}

$steps = if ($Mode -eq "development") { 5 } else { 6 }
Write-Host "[1/$steps] Checking prerequisites..."
Invoke-PrerequisiteCheck

if ($Mode -eq "development") {
    # Install npm dependencies
    Write-Host "[2/5] Installing npm dependencies..."
    Invoke-Checked "npm install" { npm install }

    # Start PostgreSQL
    Write-Host "[3/5] Starting PostgreSQL..."
    Invoke-Checked "docker compose up" { docker compose up -d segmentra-db }
    Write-Host "  Waiting for PostgreSQL..."
    $dbReady = $false
    for ($i = 0; $i -lt 30; $i++) {
        if (Test-NativeSuccess { docker compose exec -T segmentra-db pg_isready -U segmentra }) { $dbReady = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $dbReady) {
        Write-Host "ERROR: PostgreSQL did not become ready in time (docker compose logs segmentra-db)" -ForegroundColor Red
        exit 1
    }
    Write-Host "  PostgreSQL ready on port 15432"

    # Build
    Write-Host "[4/5] Building workspaces..."
    Invoke-Checked "build" { npm run build }

    # Migrate and seed
    Write-Host "[5/5] Setting up database..."
    $env:DATABASE_URL = "postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
    Invoke-Checked "db:migrate" { npm run db:migrate }
    Invoke-Checked "db:seed" { npm run db:seed }

    Write-Host ""
    Write-Host "========================================"
    Write-Host " Development installation complete!"
    Write-Host "========================================"
    Write-Host ""
    Write-Host " Start the application:"
    Write-Host "   .\run.ps1 -start -development"
    Write-Host ""
    Write-Host " Default credentials (development only):"
    Write-Host "   Username: admin"
    Write-Host "   Password: admin123 (or SEGMENTRA_ADMIN_PASSWORD if it was set during seeding)"
    Write-Host ""
    Write-Host " Optional: import demo data:"
    Write-Host "   node demo-data/seed-demo-data.js"
    Write-Host "========================================"
}
elseif ($Mode -eq "production") {
    # Generate secrets into .env (read automatically by docker compose; never commit it).
    # Existing values are kept, so re-running the installer is safe.
    Write-Host "[2/6] Preparing .env secrets..."
    $envFile = Join-Path $PSScriptRoot ".env"
    if (-not (Test-Path $envFile)) { New-Item -ItemType File -Path $envFile | Out-Null }
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    function New-RandomBytes([int]$n) { $b = New-Object byte[] $n; $rng.GetBytes($b); return ,$b }
    function New-RandomHex([int]$n) { -join ((New-RandomBytes $n) | ForEach-Object { $_.ToString("x2") }) }
    function Test-EnvKey([string]$key) {
        $text = Get-Content $envFile -Raw
        return [bool]($text -and ($text -match "(?m)^$key=."))
    }
    function Add-EnvLine([string]$line) { Add-Content -Path $envFile -Value $line }

    $newAdminPassword = ""
    if (-not (Test-EnvKey "JWT_SECRET")) { Add-EnvLine "JWT_SECRET=$(New-RandomHex 32)" }
    # Must be set BEFORE any secret is stored; changing it later makes stored secrets undecryptable.
    if (-not (Test-EnvKey "SEGMENTRA_KEK_B64")) { Add-EnvLine "SEGMENTRA_KEK_B64=$([Convert]::ToBase64String((New-RandomBytes 32)))" }
    if (-not (Test-EnvKey "POSTGRES_PASSWORD") -and -not (Test-EnvKey "DB_PASSWORD")) {
        $project = if ($env:COMPOSE_PROJECT_NAME) { $env:COMPOSE_PROJECT_NAME } else { (Split-Path $PSScriptRoot -Leaf).ToLower() }
        $prevEap = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        docker volume inspect "${project}_segmentra_pgdata" 2>&1 | Out-Null
        $volumeExists = ($LASTEXITCODE -eq 0)
        $ErrorActionPreference = $prevEap
        if ($volumeExists) {
            Write-Host "  Existing database volume found - keeping its current password (set POSTGRES_PASSWORD in .env to match it)."
        } else {
            Add-EnvLine "POSTGRES_PASSWORD=$(New-RandomHex 16)"
        }
    }
    if (-not (Test-EnvKey "SEGMENTRA_ADMIN_PASSWORD")) {
        $newAdminPassword = New-RandomHex 12
        Add-EnvLine "SEGMENTRA_ADMIN_PASSWORD=$newAdminPassword"
    }
    # Docker Desktop: the socket inside the VM is owned by root's group (0).
    if (-not (Test-EnvKey "DOCKER_GID")) { Add-EnvLine "DOCKER_GID=0" }
    Write-Host "  .env ready (JWT_SECRET, SEGMENTRA_KEK_B64, POSTGRES_PASSWORD, SEGMENTRA_ADMIN_PASSWORD, DOCKER_GID)"

    Write-Host "[3/6] Building Docker images..."
    docker compose build
    if ($LASTEXITCODE -ne 0) { throw "docker compose build failed" }

    # The db healthcheck gates the API; the API entrypoint runs migrations + seed on start.
    Write-Host "[4/6] Starting all services..."
    docker compose up -d
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }

    Write-Host "[5/6] Waiting for the API (migrations run on container start)..."
    $apiOk = $false
    for ($i = 0; $i -lt 60; $i++) {
        try {
            $null = Invoke-WebRequest -Uri "http://127.0.0.1:8080/api/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            $apiOk = $true
            break
        } catch { Start-Sleep -Seconds 2 }
    }
    if ($apiOk) { Write-Host "  API ready" } else { Write-Host "  WARNING: API not healthy yet. Check: docker compose logs segmentra-app" -ForegroundColor Yellow }

    Write-Host "[6/6] Done."
    Write-Host ""
    Write-Host "========================================"
    Write-Host " Production installation complete!"
    Write-Host "========================================"
    Write-Host ""
    Write-Host " Services running:"
    Write-Host "   UI:  http://localhost:80"
    Write-Host "   API: http://127.0.0.1:8080 (localhost only; browsers use the UI's /api proxy)"
    Write-Host "   DB:  127.0.0.1:15432"
    Write-Host ""
    Write-Host " Admin login:"
    Write-Host "   Username: admin"
    if ($newAdminPassword) {
        Write-Host "   Password: $newAdminPassword   (stored in .env as SEGMENTRA_ADMIN_PASSWORD - change it after first login)"
    } else {
        Write-Host "   Password: SEGMENTRA_ADMIN_PASSWORD from .env (used only when the admin user is first created)"
    }
    Write-Host ""
    Write-Host " SECURITY: the API container mounts /var/run/docker.sock (root-equivalent) for the"
    Write-Host " Ansible executor. If you only use the SSH executor, remove that mount from docker-compose.yml."
    Write-Host " Back up .env: losing SEGMENTRA_KEK_B64 makes stored SSH/LDAP secrets unrecoverable."
    Write-Host ""
    Write-Host " Manage services:"
    Write-Host "   .\run.ps1 -start -production"
    Write-Host "   .\run.ps1 -stop -production"
    Write-Host "========================================"
}
