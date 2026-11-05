# No param() block on purpose, like install.ps1: declared switches make -d ambiguous between
# -dev and -development, and --start would not bind to anything.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
. (Join-Path (Join-Path $PSScriptRoot "scripts") "windows-helpers.ps1")

$Action = ""
$Mode = ""
$badArgs = $false
foreach ($a in $args) {
    $opt = "$a"
    if ($opt -match '^-{1,2}(start|stop|status)$') { $Action = $Matches[1].ToLower() }
    elseif ($opt -match '^-{1,2}(d|dev|development)$') { $Mode = "development" }
    elseif ($opt -match '^-{1,2}(p|prod|production)$') { $Mode = "production" }
    else { $badArgs = $true }
}

if ($badArgs -or -not $Action -or -not $Mode) {
    Write-Host "Usage: .\run.ps1 <action> <mode>"
    Write-Host ""
    Write-Host "Actions:"
    Write-Host "  --start    Start all services"
    Write-Host "  --stop     Stop all services"
    Write-Host "  --status   Show service status"
    Write-Host ""
    Write-Host "Modes:"
    Write-Host "  --development, --dev, -d  Local dev (Node.js + Docker DB)"
    Write-Host "  --production, --prod, -p  Docker Compose (all containers)"
    Write-Host ""
    Write-Host "One or two dashes both work. Examples:"
    Write-Host "  .\run.ps1 --start --development"
    Write-Host "  .\run.ps1 -stop -production"
    exit 1
}

Add-DockerToSessionPath

# Stops with what docker itself said, instead of a generic "not running".
function Assert-Docker {
    switch (Get-DockerState) {
        "ok" { return }
        "missing" { Write-Host "ERROR: Docker was not found. Install Docker Desktop and try again." -ForegroundColor Red }
        "windows" {
            Write-Host "ERROR: Docker Desktop is in Windows containers mode." -ForegroundColor Red
            Write-WindowsContainersHint
        }
        default {
            Write-Host "ERROR: cannot use Docker. Check that Docker Desktop shows 'Engine running'." -ForegroundColor Red
            Write-DockerError
        }
    }
    exit 1
}

# Install deps when missing, refresh when a manifest is newer than the last install.
function Ensure-Deps {
    $marker = "node_modules/.package-lock.json"
    if (-not (Test-Path $marker)) {
        Write-Host "  Installing dependencies..."
        if (Test-Path "package-lock.json") { npm ci } else { npm install }
        if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
        return
    }
    $markerTime = (Get-Item $marker).LastWriteTime
    $manifests = @("package-lock.json", "package.json") +
        (Get-ChildItem -Path "apps", "packages" -Directory | ForEach-Object { Join-Path $_.FullName "package.json" })
    $stale = $manifests | Where-Object { (Test-Path $_) -and ((Get-Item $_).LastWriteTime -gt $markerTime) }
    if ($stale) {
        Write-Host "  Dependency manifests changed - running npm install..."
        npm install
        if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
    }
}

# Dev JWT secret: use $env:JWT_SECRET if set, otherwise a random secret generated once
# and stored in the untracked file .dev-jwt-secret.
function Set-DevJwtSecret {
    if ($env:JWT_SECRET) { return }
    $secretFile = Join-Path $PSScriptRoot ".dev-jwt-secret"
    if (-not (Test-Path $secretFile) -or -not (Get-Content $secretFile -Raw)) {
        $bytes = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $hex = -join ($bytes | ForEach-Object { $_.ToString("x2") })
        Set-Content -Path $secretFile -Value $hex -NoNewline
        Write-Host "  Generated development JWT secret in .dev-jwt-secret"
    }
    $env:JWT_SECRET = (Get-Content $secretFile -Raw).Trim()
}

function Invoke-Checked([string]$what, [scriptblock]$block) {
    & $block
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" }
}

if ($Mode -eq "development") {
    switch ($Action) {
        "start" {
            Write-Host "[segmentra] Starting development environment..."
            Write-Host ""
            Assert-Docker
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            $appRunning = & docker compose ps -q segmentra-app 2>$null
            $ErrorActionPreference = $prevEap
            if ($appRunning) {
                Write-Host "ERROR: the production stack is running and uses the same ports." -ForegroundColor Red
                Write-Host "  Stop it first: .\run.ps1 --stop --production"
                exit 1
            }

            Write-Host "[1/4] Checking dependencies..."
            Ensure-Deps

            Write-Host "[2/4] Starting PostgreSQL..."
            Invoke-Checked "docker compose up" { docker compose up -d segmentra-db }
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            $dbReady = $false
            for ($i = 0; $i -lt 30; $i++) {
                docker compose exec -T segmentra-db pg_isready -U segmentra 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { $dbReady = $true; break }
                Start-Sleep -Seconds 1
            }
            $ErrorActionPreference = $prevEap
            if (-not $dbReady) {
                Write-Host "ERROR: PostgreSQL did not become ready in time. Check: docker compose logs segmentra-db" -ForegroundColor Red
                exit 1
            }

            # The database password and the secret key may come from a production install's .env.
            $env:DATABASE_URL = (& node packages/db/scripts/dev-env.js database-url)
            $kek = (& node packages/db/scripts/dev-env.js get SEGMENTRA_KEK_B64)
            if ($kek) { $env:SEGMENTRA_KEK_B64 = $kek }
            if (-not $env:BUNDLES_DIR) { $env:BUNDLES_DIR = "./data/bundles" }
            # Keep the host keys of managed hosts out of the user's own ~\.ssh\known_hosts.
            if (-not $env:SEGMENTRA_KNOWN_HOSTS) { $env:SEGMENTRA_KNOWN_HOSTS = Join-Path $PSScriptRoot "data\ssh\known_hosts" }
            Set-DevJwtSecret
            New-Item -ItemType Directory -Force -Path $env:BUNDLES_DIR | Out-Null

            # Build first: the API dev server runs apps/api/dist
            Write-Host "[3/4] Migrating database and building..."
            Invoke-Checked "database connection" { node packages/db/scripts/dev-env.js check-db }
            Invoke-Checked "db:migrate" { npm run db:migrate }
            Invoke-Checked "db:seed" { npm run db:seed }
            Invoke-Checked "build" { npm run build }

            Write-Host "[4/4] Starting API and UI..."

            # Start API in background
            $apiJob = Start-Job -ScriptBlock {
                Set-Location $using:PSScriptRoot
                npm run dev -w apps/api 2>&1
            }

            # Start UI in background
            $webJob = Start-Job -ScriptBlock {
                Set-Location "$using:PSScriptRoot\apps\web"
                npm run dev 2>&1
            }

            Write-Host ""
            Write-Host "  Services starting..."
            Write-Host ""
            Write-Host "  API: http://localhost:8080"
            Write-Host "  UI:  http://localhost:5173"
            Write-Host "  DB:  localhost:$(Get-EnvValue 'DB_PORT' '15432')"
            Write-Host ""
            Write-Host "  Login: admin / admin123, unless SEGMENTRA_ADMIN_PASSWORD or an earlier install set another one"
            Write-Host ""
            Write-Host "  Press Ctrl+C to stop, then run: .\run.ps1 -stop -development"

            # Wait and show output
            try {
                while ($true) {
                    Receive-Job $apiJob -ErrorAction SilentlyContinue
                    Receive-Job $webJob -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                }
            } finally {
                Stop-Job $apiJob, $webJob -ErrorAction SilentlyContinue
                Remove-Job $apiJob, $webJob -Force -ErrorAction SilentlyContinue
            }
        }
        "stop" {
            Write-Host "[segmentra] Stopping development environment..."
            # Node processes started from this checkout. The node.exe path never contains the
            # repository, so match on the command line (vite runs from the repo path). The API
            # (node --watch dist/index.js) has no repository path in it, so also look at what
            # listens on its port, but only a dist/index.js: another project may use 8080 too.
            $root = [regex]::Escape($PSScriptRoot)
            $pids = @()
            $pids += Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -match $root } |
                ForEach-Object { $_.ProcessId }
            $portPids = Get-NetTCPConnection -State Listen -LocalPort 8080 -ErrorAction SilentlyContinue |
                ForEach-Object { $_.OwningProcess } |
                Where-Object { (Get-CimInstance Win32_Process -Filter "ProcessId = $_" -ErrorAction SilentlyContinue).CommandLine -match 'dist[\\/]+index\.js' }
            foreach ($p in $portPids) {
                # Also stop the node parents (node --watch restarts its child; npm run waits on it).
                $cur = $p
                for ($depth = 0; $depth -lt 3 -and $cur; $depth++) {
                    $pids += $cur
                    $parent = (Get-CimInstance Win32_Process -Filter "ProcessId = $cur" -ErrorAction SilentlyContinue).ParentProcessId
                    $cur = if ($parent -and (Get-Process -Id $parent -ErrorAction SilentlyContinue).ProcessName -eq 'node') { $parent } else { $null }
                }
            }
            $pids | Sort-Object -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
            docker compose stop segmentra-db
            Write-Host "  All services stopped"
        }
        "status" {
            Write-Host "[segmentra] Development environment status:"
            Write-Host ""
            Write-Host "  PostgreSQL:"
            # Stderr redirection under "Stop" is a terminating error on Windows PowerShell 5.1.
            $ErrorActionPreference = "Continue"
            docker compose ps segmentra-db 2>$null
            $ErrorActionPreference = "Stop"
            Write-Host ""
            Write-Host "  API (port 8080):"
            try { $null = Invoke-WebRequest -Uri "http://localhost:8080/api/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop; Write-Host "    Running" } catch { Write-Host "    Not running" }
            Write-Host ""
            Write-Host "  UI (port 5173):"
            try { $null = Invoke-WebRequest -Uri "http://localhost:5173" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop; Write-Host "    Running" } catch { Write-Host "    Not running" }
        }
    }
}
elseif ($Mode -eq "production") {
    switch ($Action) {
        "start" {
            Write-Host "[segmentra] Starting production environment..."
            Assert-Docker
            $envFile = Join-Path $PSScriptRoot ".env"
            $envText = if (Test-Path $envFile) { Get-Content $envFile -Raw } else { "" }
            if (-not $envText) { $envText = "" }
            $hasJwt = $env:JWT_SECRET -or ($envText -match '(?m)^JWT_SECRET=.')
            $hasKek = $env:SEGMENTRA_KEK_B64 -or ($envText -match '(?m)^SEGMENTRA_KEK_B64=.')
            if (-not ($hasJwt -and $hasKek)) {
                Write-Host "  WARNING: JWT_SECRET and/or SEGMENTRA_KEK_B64 are not set (environment or .env)." -ForegroundColor Yellow
                Write-Host "           The API container will refuse to start. Run .\install.ps1 --production to generate them." -ForegroundColor Yellow
            }
            # The API container entrypoint runs database migrations and the seed on every start.
            docker compose up -d
            if ($LASTEXITCODE -ne 0) {
                Write-Host "ERROR: docker compose up failed (see above)." -ForegroundColor Red
                exit 1
            }
            Write-Host ""
            Write-Host "  Services started (the API runs migrations on startup: docker compose logs -f segmentra-app)"
            Write-Host "  UI:  http://localhost:$(Get-EnvValue 'WEB_PORT' '80')"
            Write-Host "  API: http://127.0.0.1:$(Get-EnvValue 'API_PORT' '8080')"
            Write-Host ""
            docker compose ps
        }
        "stop" {
            Write-Host "[segmentra] Stopping production environment..."
            docker compose stop
            Write-Host "  All services stopped"
        }
        "status" {
            Write-Host "[segmentra] Production environment status:"
            Write-Host ""
            docker compose ps
        }
    }
}
