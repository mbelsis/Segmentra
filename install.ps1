param(
    [Parameter(Position=0)]
    [ValidateSet("--development", "--production", "--dev", "--prod", "-d", "-p")]
    [string]$Mode = "--development"
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# Normalize
switch ($Mode) {
    { $_ -in "--development", "--dev", "-d" } { $Mode = "development" }
    { $_ -in "--production", "--prod", "-p" } { $Mode = "production" }
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

# Check Docker
Write-Host "[1/6] Checking Docker..."
if (-not (Test-NativeSuccess { docker info })) {
    Write-Host "ERROR: Docker is not running. Please start Docker Desktop and try again." -ForegroundColor Red
    exit 1
}
Write-Host "  Docker OK"

if ($Mode -eq "development") {
    # Check Node.js
    Write-Host "[2/6] Checking Node.js..."
    try { $nodeVersion = (node -v) -replace 'v','' } catch {
        Write-Host "ERROR: Node.js is not installed. Install Node.js 20+ from https://nodejs.org" -ForegroundColor Red
        exit 1
    }
    $major = [int]($nodeVersion.Split('.')[0])
    if ($major -lt 20) {
        Write-Host "ERROR: Node.js 20+ required. Found: v$nodeVersion" -ForegroundColor Red
        exit 1
    }
    Write-Host "  Node.js v$nodeVersion OK"

    # Install npm dependencies
    Write-Host "[3/6] Installing npm dependencies..."
    Invoke-Checked "npm install" { npm install }

    # Start PostgreSQL
    Write-Host "[4/6] Starting PostgreSQL..."
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
    Write-Host "[5/6] Building workspaces..."
    Invoke-Checked "build" { npm run build }

    # Migrate and seed
    Write-Host "[6/6] Setting up database..."
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
