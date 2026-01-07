@echo off
setlocal

REM Segmentra dev launcher (Windows)
cd /d "%~dp0"

set "MODE=%~1"
echo [segmentra] Starting dev environment... (mode=%MODE%)

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
if /I "%MODE%"=="dev" if "%SEGMENTRA_BOOTSTRAP_TOKEN%"=="" set "SEGMENTRA_BOOTSTRAP_TOKEN=dev-bootstrap-token"

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
if /I "%MODE%"=="dev" goto :bootstrap
echo [segmentra] Tip: run "start.bat dev" to bootstrap a JWT and bypass LDAP in the UI.
goto :done

:bootstrap
echo [segmentra] Dev mode: bootstrapping admin token (no LDAP)...
set "TRY=0"

:wait_api
set /a TRY=TRY+1
if %TRY% GTR 60 goto :bootstrap_fail
powershell -NoProfile -Command "$ErrorActionPreference='Stop'; Invoke-RestMethod -Uri 'http://localhost:8080/api/health' | Out-Null"
if errorlevel 1 (
  timeout /t 1 /nobreak >nul
  goto :wait_api
)

powershell -NoProfile -Command "$ErrorActionPreference='Stop'; $body=@{token='%SEGMENTRA_BOOTSTRAP_TOKEN%';username='bootstrap_admin'}|ConvertTo-Json; $r=Invoke-RestMethod -Method Post -Uri 'http://localhost:8080/api/admin/bootstrap' -ContentType 'application/json' -Body $body; if ($null -ne $r.token) { $r.token | Out-File -Encoding ascii .dev-admin-jwt.txt; Write-Host ('[segmentra] Wrote JWT to .dev-admin-jwt.txt'); Write-Host ('[segmentra] In browser DevTools console run:'); Write-Host (\"localStorage.setItem('segmentra_token','\" + $r.token + \"'); location.reload()\"); } else { Write-Host '[segmentra] Bootstrap did not return a token (maybe already initialized).'; }"
goto :done

:bootstrap_fail
echo [segmentra] Could not reach API /api/health to bootstrap. You can bootstrap manually later.
goto :done

:done
echo.

endlocal


