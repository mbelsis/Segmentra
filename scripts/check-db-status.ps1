# Database Status Check Script
# This script helps diagnose database issues

Write-Host "=== Segmentra Database Status Check ===" -ForegroundColor Cyan
Write-Host ""

# Check Docker container
Write-Host "1. Checking Docker container..." -ForegroundColor Yellow
$container = docker ps --filter "name=segmentra-db" --format "{{.Names}}" 2>&1
if ($container) {
    Write-Host "   ✓ Container running: $container" -ForegroundColor Green
} else {
    Write-Host "   ✗ Container not running!" -ForegroundColor Red
    exit 1
}

# Check database connection
Write-Host ""
Write-Host "2. Checking database connection..." -ForegroundColor Yellow
$dbCheck = docker exec segmentra-segmentra-db-1 psql -U segmentra -d segmentra -c "SELECT current_database(), version();" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "   ✓ Database connection successful" -ForegroundColor Green
} else {
    Write-Host "   ✗ Database connection failed!" -ForegroundColor Red
    Write-Host "   Error: $dbCheck" -ForegroundColor Red
    exit 1
}

# Check data counts
Write-Host ""
Write-Host "3. Checking data counts..." -ForegroundColor Yellow
$counts = docker exec segmentra-segmentra-db-1 psql -U segmentra -d segmentra -t -c @"
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
$migrations = docker exec segmentra-segmentra-db-1 psql -U segmentra -d segmentra -c "SELECT COUNT(DISTINCT name) as unique_migrations, COUNT(*) as total_runs FROM pgmigrations;" 2>&1
Write-Host $migrations

# Check for duplicate migrations
Write-Host ""
Write-Host "5. Checking for duplicate migrations..." -ForegroundColor Yellow
$duplicates = docker exec segmentra-segmentra-db-1 psql -U segmentra -d segmentra -c "SELECT name, COUNT(*) as runs FROM pgmigrations GROUP BY name HAVING COUNT(*) > 1;" 2>&1
if ($duplicates -match "rows\)") {
    Write-Host "   ⚠ Found duplicate migrations:" -ForegroundColor Yellow
    Write-Host $duplicates
} else {
    Write-Host "   ✓ No duplicate migrations" -ForegroundColor Green
}

# Check volume info
Write-Host ""
Write-Host "6. Checking volume information..." -ForegroundColor Yellow
$volumeInfo = docker volume inspect segmentra_segmentra_pgdata --format='Created: {{.CreatedAt}}' 2>&1
Write-Host "   $volumeInfo"

Write-Host ""
Write-Host "=== Check Complete ===" -ForegroundColor Cyan
