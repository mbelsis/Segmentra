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

if ($Mode -eq "development") {
    switch ($Action) {
        "start" {
            Write-Host "[segmentra] Starting development environment..."
            Write-Host ""

            Write-Host "[1/3] Starting PostgreSQL..."
            docker compose up -d segmentra-db
            Start-Sleep -Seconds 3

            Write-Host "[2/3] Starting API and UI..."
            $env:DATABASE_URL = "postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
            $env:JWT_SECRET = "dev-secret-change-me-in-production"
            $env:BUNDLES_DIR = "./data/bundles"

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
            Write-Host "[3/3] Services starting..."
            Write-Host ""
            Write-Host "  API: http://localhost:8080"
            Write-Host "  UI:  http://localhost:5173"
            Write-Host "  DB:  localhost:15432"
            Write-Host ""
            Write-Host "  Login: admin / admin123"
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
            Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object { $_.Path -match "segmentra" } | Stop-Process -Force -ErrorAction SilentlyContinue
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
            docker compose up -d
            Write-Host ""
            Write-Host "  UI:  http://localhost:80"
            Write-Host "  API: http://localhost:8080"
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
