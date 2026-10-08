# Database Status Check Script
# This script helps diagnose database issues. Run it from anywhere; it uses the
# repository's docker-compose.yml (service "segmentra-db").

Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "=== Segmentra Database Status Check ===" -ForegroundColor Cyan
Write-Host ""

# Check Docker container
Write-Host "1. Checking Docker container..." -ForegroundColor Yellow
$container = docker compose ps -q segmentra-db 2>$null
if ($container) {
    Write-Host "   [OK] Container running: $container" -ForegroundColor Green
} else {
    Write-Host "   [FAIL] Container not running!" -ForegroundColor Red
    exit 1
}

# Check database connection
Write-Host ""
Write-Host "2. Checking database connection..." -ForegroundColor Yellow
$dbCheck = docker compose exec -T segmentra-db psql -U segmentra -d segmentra -c "SELECT current_database(), version();" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "   [OK] Database connection successful" -ForegroundColor Green
} else {
    Write-Host "   [FAIL] Database connection failed!" -ForegroundColor Red
    Write-Host "   Error: $dbCheck" -ForegroundColor Red
    exit 1
}

# Check data counts
Write-Host ""
Write-Host "3. Checking data counts..." -ForegroundColor Yellow
$counts = docker compose exec -T segmentra-db psql -U segmentra -d segmentra -t -c @"
SELECT 
    'hosts' as table_name, COUNT(*) as count FROM hosts
UNION ALL
SELECT 'vlans', COUNT(*) FROM vlans
UNION ALL
SELECT 'tags', COUNT(*) FROM tags
UNION ALL
SELECT 'policy_sets', COUNT(*) FROM policy_sets
UNION ALL
SELECT 'policy_versions', COUNT(*) FROM policy_versions
UNION ALL
SELECT 'users', COUNT(*) FROM users;
"@ 2>&1

Write-Host $counts

# Check migrations
Write-Host ""
Write-Host "4. Checking migrations..." -ForegroundColor Yellow
$migrations = docker compose exec -T segmentra-db psql -U segmentra -d segmentra -c "SELECT COUNT(DISTINCT name) as unique_migrations, COUNT(*) as total_runs FROM pgmigrations;" 2>&1
Write-Host $migrations

# Check for duplicate migrations. Older releases shipped NNN_x.js wrappers next to
# NNN_x.sql, so each migration was recorded twice; `npm run db:migrate` now removes
# those duplicate history rows, so this should report none.
Write-Host ""
Write-Host "5. Checking for duplicate migrations..." -ForegroundColor Yellow
$duplicates = docker compose exec -T segmentra-db psql -U segmentra -d segmentra -t -A -c "SELECT name || ' (' || COUNT(*) || ' runs)' FROM pgmigrations GROUP BY name HAVING COUNT(*) > 1 ORDER BY name;" 2>&1
$duplicates = @($duplicates | Where-Object { "$_".Trim() -ne "" })
if ($duplicates.Count -gt 0) {
    Write-Host "   [WARN] Found duplicate migrations (run 'npm run db:migrate' to clean up):" -ForegroundColor Yellow
    $duplicates | ForEach-Object { Write-Host "     $_" }
} else {
    Write-Host "   [OK] No duplicate migrations" -ForegroundColor Green
}

# Check volume info
Write-Host ""
Write-Host "6. Checking volume information..." -ForegroundColor Yellow
$volumeName = docker inspect $container --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}' 2>&1
$volumeInfo = docker volume inspect $volumeName --format='Volume: {{.Name}}  Created: {{.CreatedAt}}' 2>&1
Write-Host "   $volumeInfo"

Write-Host ""
Write-Host "=== Check Complete ===" -ForegroundColor Cyan
