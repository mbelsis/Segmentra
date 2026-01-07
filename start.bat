@echo off
setlocal

REM Segmentra dev launcher (Windows)
cd /d "%~dp0"

echo [segmentra] Starting dev environment...

REM Avoid parenthesized blocks to prevent common batch parser errors.
if not exist node_modules echo [segmentra] Installing dependencies (npm install)...
if not exist node_modules call npm install
if errorlevel 1 exit /b 1

REM Optional: wipe local dev DB volume (DATA LOSS) if SEGMENTRA_RESET_DB=1
if "%SEGMENTRA_RESET_DB%"=="1" echo [segmentra] SEGMENTRA_RESET_DB=1 -> removing docker volumes (DATA LOSS)...
if "%SEGMENTRA_RESET_DB%"=="1" docker compose down -v

echo [segmentra] Starting Postgres (docker compose)...
docker compose up -d segmentra-db
if errorlevel 1 exit /b 1

REM Defaults (override by setting env vars before running start.bat)
REM Use SEGMENTRA_DATABASE_URL if provided, otherwise use the local compose DB.
if not "%SEGMENTRA_DATABASE_URL%"=="" set "DATABASE_URL=%SEGMENTRA_DATABASE_URL%"
if "%SEGMENTRA_DATABASE_URL%"=="" set "DATABASE_URL=postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"

if "%JWT_SECRET%"=="" set "JWT_SECRET=change-me-to-a-long-random-string"
if "%SEGMENTRA_BOOTSTRAP_TOKEN%"=="" set "SEGMENTRA_BOOTSTRAP_TOKEN=dev-bootstrap-token"

echo [segmentra] Using DATABASE_URL=%DATABASE_URL%

echo [segmentra] Running migrations + seeding roles...
call npm run db:migrate
if errorlevel 1 exit /b 1
call npm run db:seed
if errorlevel 1 exit /b 1

echo [segmentra] Building workspaces...
call npm run build -ws
if errorlevel 1 exit /b 1

echo [segmentra] Launching API (new window)...
start "segmentra-api" cmd /k "cd /d ""%~dp0"" && set ""DATABASE_URL=%DATABASE_URL%"" && set ""JWT_SECRET=%JWT_SECRET%"" && set ""SEGMENTRA_BOOTSTRAP_TOKEN=%SEGMENTRA_BOOTSTRAP_TOKEN%"" && npm run dev -w apps/api"

echo [segmentra] Launching UI (new window)...
start "segmentra-web" cmd /k "cd /d ""%~dp0apps\web"" && npm run dev"

echo.
echo [segmentra] API health: http://localhost:8080/api/health
echo.
echo [segmentra] To access the UI without LDAP (bootstrap):
echo   1) Wait for API to be up, then run in PowerShell:
echo      $body = @{ token="%SEGMENTRA_BOOTSTRAP_TOKEN%"; username="bootstrap_admin" } ^| ConvertTo-Json
echo      Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/admin/bootstrap" -ContentType "application/json" -Body $body
echo   2) Copy token, then in browser DevTools console:
echo      localStorage.setItem('segmentra_token','PASTE_TOKEN'); location.reload()
echo.

endlocal


