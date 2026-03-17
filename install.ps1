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

# Check Docker
Write-Host "[1/6] Checking Docker..."
try { docker info 2>&1 | Out-Null } catch {
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
    npm install

    # Start PostgreSQL
    Write-Host "[4/6] Starting PostgreSQL..."
    docker compose up -d segmentra-db
    Write-Host "  Waiting for PostgreSQL..."
    Start-Sleep -Seconds 5
    for ($i = 0; $i -lt 20; $i++) {
        $result = docker compose exec -T segmentra-db pg_isready -U segmentra 2>&1
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep -Seconds 1
    }
    Write-Host "  PostgreSQL ready on port 15432"

    # Build
    Write-Host "[5/6] Building workspaces..."
    npm run build

    # Migrate and seed
    Write-Host "[6/6] Setting up database..."
    $env:DATABASE_URL = "postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
    npm run db:migrate
    npm run db:seed

    Write-Host ""
    Write-Host "========================================"
    Write-Host " Development installation complete!"
    Write-Host "========================================"
    Write-Host ""
    Write-Host " Start the application:"
    Write-Host "   .\run.ps1 --start --development"
    Write-Host ""
    Write-Host " Default credentials:"
    Write-Host "   Username: admin"
    Write-Host "   Password: admin123"
    Write-Host ""
    Write-Host " Optional: import demo data:"
    Write-Host "   node demo-data/seed-demo-data.js"
    Write-Host "========================================"
}
elseif ($Mode -eq "production") {
    Write-Host "[2/6] Building Docker images..."
    docker compose build

    Write-Host "[3/6] Starting all services..."
    docker compose up -d

    Write-Host "[4/6] Waiting for PostgreSQL..."
    Start-Sleep -Seconds 5
    for ($i = 0; $i -lt 30; $i++) {
        $result = docker compose exec -T segmentra-db pg_isready -U segmentra 2>&1
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep -Seconds 1
    }
    Write-Host "  PostgreSQL ready"

    Write-Host "[5/6] Running database migrations..."
    docker compose exec -T segmentra-app sh -c "cd /app && DATABASE_URL=postgres://segmentra:segmentra@segmentra-db:5432/segmentra node node_modules/.bin/node-pg-migrate up -m packages/db/migrations"

    Write-Host "[6/6] Seeding default data..."
    docker compose exec -T segmentra-app sh -c "cd /app && DATABASE_URL=postgres://segmentra:segmentra@segmentra-db:5432/segmentra node packages/db/scripts/seed-roles.js"

    Write-Host ""
    Write-Host "========================================"
    Write-Host " Production installation complete!"
    Write-Host "========================================"
    Write-Host ""
    Write-Host " Services running:"
    Write-Host "   UI:  http://localhost:80"
    Write-Host "   API: http://localhost:8080"
    Write-Host "   DB:  localhost:15432"
    Write-Host ""
    Write-Host " Default credentials:"
    Write-Host "   Username: admin"
    Write-Host "   Password: admin123"
    Write-Host ""
    Write-Host " Manage services:"
    Write-Host "   .\run.ps1 --start --production"
    Write-Host "   .\run.ps1 --stop --production"
    Write-Host "========================================"
}
