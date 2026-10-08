param(
    [switch]$start,
    [switch]$stop,
    [switch]$status,
    [switch]$development,
    [switch]$dev,
    [switch]$production,
    [switch]$prod
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# Normalize
$Action = if ($start) { "start" } elseif ($stop) { "stop" } elseif ($status) { "status" } else { "" }
$Mode = if ($development -or $dev) { "development" } elseif ($production -or $prod) { "production" } else { "" }

if (-not $Action -or -not $Mode) {
    Write-Host "Usage: .\run.ps1 <action> <mode>"
    Write-Host ""
    Write-Host "Actions:"
    Write-Host "  -start    Start all services"
    Write-Host "  -stop     Stop all services"
    Write-Host "  -status   Show service status"
    Write-Host ""
    Write-Host "Modes:"
    Write-Host "  -development  Local dev (Node.js + Docker DB)"
    Write-Host "  -production   Docker Compose (all containers)"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\run.ps1 -start -development"
    Write-Host "  .\run.ps1 -stop -production"
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

            Write-Host "[1/4] Checking dependencies..."
            Ensure-Deps

            Write-Host "[2/4] Starting PostgreSQL..."
            Invoke-Checked "docker compose up" { docker compose up -d segmentra-db }
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            for ($i = 0; $i -lt 30; $i++) {
                docker compose exec -T segmentra-db pg_isready -U segmentra 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { break }
                Start-Sleep -Seconds 1
            }
            $ErrorActionPreference = $prevEap

            $env:DATABASE_URL = if ($env:SEGMENTRA_DATABASE_URL) { $env:SEGMENTRA_DATABASE_URL } else { "postgres://segmentra:segmentra@127.0.0.1:15432/segmentra" }
            if (-not $env:BUNDLES_DIR) { $env:BUNDLES_DIR = "./data/bundles" }
            Set-DevJwtSecret
            New-Item -ItemType Directory -Force -Path $env:BUNDLES_DIR | Out-Null

            # Build first: the API dev server runs apps/api/dist
            Write-Host "[3/4] Migrating database and building..."
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
            Write-Host "  DB:  localhost:15432"
            Write-Host ""
            Write-Host "  Login: admin / admin123 (dev default unless SEGMENTRA_ADMIN_PASSWORD was set on first seed)"
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
            # repository, so match on the command line (vite runs from the repo path) and on the
            # dev ports 8080 (API: node --watch dist/index.js) and 5173 (UI), in case a background
            # job left an orphaned node process behind.
            $root = [regex]::Escape($PSScriptRoot)
            $pids = @()
            $pids += Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -match $root } |
                ForEach-Object { $_.ProcessId }
            $portPids = Get-NetTCPConnection -State Listen -LocalPort 8080, 5173 -ErrorAction SilentlyContinue |
                ForEach-Object { $_.OwningProcess } |
                Where-Object { (Get-Process -Id $_ -ErrorAction SilentlyContinue).ProcessName -eq 'node' }
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
            docker compose ps segmentra-db 2>$null
            Write-Host ""
            Write-Host "  API (port 8080):"
            try { $null = Invoke-WebRequest -Uri "http://localhost:8080/api/health" -TimeoutSec 2 -ErrorAction Stop; Write-Host "    Running" } catch { Write-Host "    Not running" }
            Write-Host ""
            Write-Host "  UI (port 5173):"
            try { $null = Invoke-WebRequest -Uri "http://localhost:5173" -TimeoutSec 2 -ErrorAction Stop; Write-Host "    Running" } catch { Write-Host "    Not running" }
        }
    }
}
elseif ($Mode -eq "production") {
    switch ($Action) {
        "start" {
            Write-Host "[segmentra] Starting production environment..."
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
            Write-Host ""
            Write-Host "  Services started (the API runs migrations on startup: docker compose logs -f segmentra-app)"
            Write-Host "  UI:  http://localhost:80"
            Write-Host "  API: http://127.0.0.1:8080"
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
