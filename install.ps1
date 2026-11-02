# No param() block on purpose: the options are read from $args. A declared parameter with
# [Parameter()] makes this an advanced script, and PowerShell then claims -d for -Debug and
# rejects -p as ambiguous (-ProgressAction, -PipelineVariable) before any of this code runs.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
. (Join-Path (Join-Path $PSScriptRoot "scripts") "windows-helpers.ps1")

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

# Docker Desktop is open but its engine does not answer: it may still be starting.
function Wait-ForDockerEngine {
    Write-Host "  Docker Desktop is running. Waiting for its engine (up to 2 minutes)..."
    for ($i = 0; $i -lt 60; $i++) {
        if ((Get-DockerState) -eq "ok") { return $true }
        Start-Sleep -Seconds 2
    }
    Write-Host "  ERROR: Docker Desktop is running, but docker cannot reach its engine." -ForegroundColor Red
    Write-DockerError
    Write-Host "            Check that Docker Desktop shows 'Engine running', then look at the output of:"
    Write-Host "              docker version"
    Write-Host "              docker context ls      (fix a wrong one with: docker context use desktop-linux)"
    Write-Host '              $env:DOCKER_HOST       (should normally be empty)'
    return $false
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
    $exe = Find-InDockerInstallDirs "Docker Desktop.exe"
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
    Add-DockerToSessionPath
    $state = Get-DockerState
    switch ($state) {
        "ok"      { Write-Host "  [ok]      Docker is running" }
        "stopped" { Write-Host "  [stopped] Docker is installed but not running"; Write-DockerError; $failed = $true }
        "starting" { Write-Host "  [waiting] Docker Desktop is running, but its engine is not answering"; Write-DockerError; $failed = $true }
        "windows" {
            Write-Host "  [blocked] Docker Desktop is in Windows containers mode"
            Write-WindowsContainersHint
            $blocked = $true; $failed = $true
        }
        "denied"  {
            Write-Host "  [blocked] Docker is running but this user may not use it"
            Write-DockerError
            Write-Host "            Add the user to the docker-users group, then sign out and in again."
            $blocked = $true; $failed = $true
        }
        "missing" {
            Write-DockerMissing
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

    if ($state -eq "starting" -and -not (Wait-ForDockerEngine)) { exit 1 }
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
    Write-Host "  PostgreSQL ready"

    # Build
    Write-Host "[4/5] Building workspaces..."
    Invoke-Checked "build" { npm run build }

    # Migrate and seed
    Write-Host "[5/5] Setting up database..."
    # The database takes its password from .env, which a production install may have written.
    $env:DATABASE_URL = (& node packages/db/scripts/dev-env.js database-url)
    Invoke-Checked "database connection" { node packages/db/scripts/dev-env.js check-db }
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
    Write-Host "   Password: admin123, unless SEGMENTRA_ADMIN_PASSWORD or an earlier install set another one"
    Write-Host ""
    Write-Host " Optional: import demo data:"
    Write-Host "   npm run db:demo"
    Write-Host "========================================"
}
elseif ($Mode -eq "production") {
    # Generate secrets into .env (read automatically by docker compose; never commit it).
    # Existing values are kept, so re-running the installer is safe.
    Write-Host "[2/6] Preparing .env secrets..."
    # An existing database only works with the .env it was created with: new secrets would not
    # match its password or the credentials stored in it. Stop before writing anything.
    $pgVolume = "$(Get-ComposeProject)_segmentra_pgdata"
    $dbExists = Test-NativeSuccess { docker volume inspect $pgVolume }
    if ($dbExists -and -not (Get-EnvValue "SEGMENTRA_KEK_B64" "")) {
        Write-Host "ERROR: found an existing Segmentra database (Docker volume $pgVolume), but no .env that goes with it." -ForegroundColor Red
        Write-Host "  New secrets would not match its password or the credentials stored in it. Nothing was changed."
        Write-Host "  Keep the data:  copy .env from the earlier install into this folder, then run this again."
        Write-Host "  Start over:     docker compose down -v     (DELETES all Segmentra data in that database)"
        Write-Host "  A development install has no .env; see 'Moving from development to production' in docs/installation.md."
        exit 1
    }
    $envFile = Join-Path $PSScriptRoot ".env"
    if (-not (Test-Path $envFile)) { New-Item -ItemType File -Path $envFile | Out-Null }
    # Make sure appended lines start on a new line (Notepad saves without a final newline).
    $envText = Get-Content $envFile -Raw
    if ($envText -and -not $envText.EndsWith("`n")) { Add-Content -Path $envFile -Value "" }
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
        if ($dbExists) {
            Write-Host "  Existing database volume found - keeping its current password (set POSTGRES_PASSWORD in .env to match it)."
        } else {
            Add-EnvLine "POSTGRES_PASSWORD=$(New-RandomHex 16)"
        }
    }
    if (-not (Test-EnvKey "SEGMENTRA_ADMIN_PASSWORD")) {
        $generatedPassword = New-RandomHex 12
        Add-EnvLine "SEGMENTRA_ADMIN_PASSWORD=$generatedPassword"
        # It is only used when the admin user is first created, so don't announce it otherwise.
        if (-not $dbExists) { $newAdminPassword = $generatedPassword }
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
    # Asked from inside the nginx container, so it covers nginx, the API and the migrations,
    # and does not depend on the published ports or a proxy on this machine.
    $apiOk = $false
    for ($i = 0; $i -lt 60; $i++) {
        if (Test-NativeSuccess { docker compose exec -T segmentra-web wget -q -O /dev/null http://127.0.0.1/api/health }) { $apiOk = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $apiOk) {
        Write-Host "ERROR: the API did not become healthy in 2 minutes. Last log lines:" -ForegroundColor Red
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        # Search more than is shown: a stack trace can push the actual error out of the last lines.
        $logLines = @(& docker compose logs --tail 200 segmentra-app 2>&1 | ForEach-Object { "$_" })
        $ErrorActionPreference = $prevEap
        $logLines | Select-Object -Last 20 | ForEach-Object { Write-Host $_ }
        $logs = $logLines -join "`n"
        if ($logs -match 'password authentication failed') {
            Write-Host "The database was created with a different password than the one in .env." -ForegroundColor Yellow
            Write-Host "  Keep the data:  put the earlier install's .env in this folder, then run this again."
            Write-Host "  Start over:     docker compose down -v     (DELETES all Segmentra data in that database)"
        }
        exit 1
    }
    Write-Host "  API ready"

    Write-Host "[6/6] Done."
    Write-Host ""
    Write-Host "========================================"
    Write-Host " Production installation complete!"
    Write-Host "========================================"
    Write-Host ""
    Write-Host " Services running:"
    Write-Host "   UI:  http://localhost:$(Get-EnvValue 'WEB_PORT' '80')"
    Write-Host "   API: http://127.0.0.1:$(Get-EnvValue 'API_PORT' '8080') (localhost only; browsers use the UI's /api proxy)"
    Write-Host "   DB:  127.0.0.1:$(Get-EnvValue 'DB_PORT' '15432')"
    Write-Host ""
    Write-Host " Admin login:"
    Write-Host "   Username: admin"
    if ($newAdminPassword) {
        Write-Host "   Password: $newAdminPassword   (stored in .env as SEGMENTRA_ADMIN_PASSWORD - change it after first login)"
    } elseif ($dbExists) {
        Write-Host "   Password: unchanged, this database already existed"
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
