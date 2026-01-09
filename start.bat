@echo off
setlocal enabledelayedexpansion

REM Segmentra launcher (Windows)
REM Usage: start.bat [dev|prod]
REM   dev  - Development mode with bootstrap token
REM   prod - Production mode (no bootstrap)

cd /d "%~dp0"

set "MODE=%~1"
if "%MODE%"=="" set "MODE=dev"
if /I not "%MODE%"=="dev" if /I not "%MODE%"=="prod" (
    echo [segmentra] ERROR: Invalid mode. Use: start.bat dev  or  start.bat prod
    exit /b 1
)

echo [segmentra] ========================================
echo [segmentra] Starting Segmentra in %MODE% mode
echo [segmentra] ========================================
echo.

REM Check if Docker is running
echo [segmentra] Checking Docker...
docker info >nul 2>&1
if errorlevel 1 (
    echo [segmentra] ERROR: Docker is not running!
    echo [segmentra] Please start Docker Desktop and try again.
    exit /b 1
)
echo [segmentra] Docker check passed
echo.

REM Install dependencies if needed
if exist node_modules goto skip_npm_install
echo [segmentra] Installing dependencies...
call npm install
if errorlevel 1 (
    echo [segmentra] ERROR: Failed to install dependencies
    exit /b 1
)
echo [segmentra] Dependencies installed - OK
echo.
:skip_npm_install

REM Optional: wipe local dev DB volume (DATA LOSS) if SEGMENTRA_RESET_DB=1
if not "%SEGMENTRA_RESET_DB%"=="1" goto skip_reset_db
echo [segmentra] WARNING: SEGMENTRA_RESET_DB=1 - removing docker volumes (DATA LOSS)...
docker compose down -v
echo.
:skip_reset_db

REM Start PostgreSQL container
echo [segmentra] Starting PostgreSQL (docker compose)...
docker compose up -d segmentra-db
if errorlevel 1 (
    echo [segmentra] ERROR: Failed to start PostgreSQL container
    exit /b 1
)

REM Wait for PostgreSQL to be ready
echo [segmentra] Waiting for PostgreSQL to be ready...
set "TRY=0"
:wait_db
set /a TRY=TRY+1
if %TRY% GTR 30 (
    echo [segmentra] ERROR: PostgreSQL did not become ready in time
    exit /b 1
)
docker exec segmentra-segmentra-db-1 pg_isready -U segmentra >nul 2>&1
if errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto :wait_db
)
echo [segmentra] PostgreSQL is ready - OK
echo.

REM Set up environment variables
REM Use SEGMENTRA_DATABASE_URL if provided, otherwise use the local compose DB.
if not "%SEGMENTRA_DATABASE_URL%"=="" goto use_custom_db
set "DATABASE_URL=postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
goto db_url_set
:use_custom_db
set "DATABASE_URL=%SEGMENTRA_DATABASE_URL%"
:db_url_set

if "%JWT_SECRET%"=="" set "JWT_SECRET=change-me-to-a-long-random-string"

REM Set optional environment variables with defaults
if "%PORT%"=="" set "PORT=8080"
if "%BUNDLES_DIR%"=="" set "BUNDLES_DIR=./data/bundles"
if "%ANSIBLE_RUNNER_CONTAINER%"=="" set "ANSIBLE_RUNNER_CONTAINER=segmentra-ansible-runner"

echo [segmentra] Configuration:
echo [segmentra]   DATABASE_URL=%DATABASE_URL%
echo [segmentra]   PORT=%PORT%
echo [segmentra]   MODE=%MODE%
echo.

REM Run migrations
echo [segmentra] Running database migrations...
call npm run db:migrate
if errorlevel 1 (
    echo [segmentra] ERROR: Database migrations failed
    exit /b 1
)
echo [segmentra] Migrations complete - OK
echo.

REM Seed roles
echo [segmentra] Seeding database roles...
call npm run db:seed
if errorlevel 1 (
    echo [segmentra] ERROR: Database seeding failed
    exit /b 1
)
echo [segmentra] Roles seeded - OK
echo.

REM Build workspaces
echo [segmentra] Building workspaces...
call npm run build -ws
if errorlevel 1 (
    echo [segmentra] ERROR: Build failed
    exit /b 1
)
echo [segmentra] Build complete - OK
echo.

REM Launch API in new window with all environment variables
echo [segmentra] Launching API (new window)...
start "Segmentra API" cmd /k "cd /d ""%~dp0"" && set ""DATABASE_URL=%DATABASE_URL%"" && set ""JWT_SECRET=%JWT_SECRET%"" && set ""PORT=%PORT%"" && set ""BUNDLES_DIR=%BUNDLES_DIR%"" && set ""ANSIBLE_RUNNER_CONTAINER=%ANSIBLE_RUNNER_CONTAINER%"" && echo [API] Starting on port %PORT%... && npm run dev -w apps/api"

REM Launch UI in new window
echo [segmentra] Launching UI (new window)...
start "Segmentra UI" cmd /k "cd /d ""%~dp0apps\web"" && echo [UI] Starting Vite dev server... && npm run dev"

echo.
echo [segmentra] ========================================
echo [segmentra] Setup complete!
echo [segmentra] ========================================
echo.
echo [segmentra] Services:
echo [segmentra]   API: http://localhost:%PORT%/api/health
echo [segmentra]   UI:  http://localhost:5173 (check terminal window)
echo.

echo [segmentra] ========================================
echo [segmentra] Default Login Credentials
echo [segmentra] ========================================
echo [segmentra] Username: admin
echo [segmentra] Password: admin
echo.
echo [segmentra] IMPORTANT: Change the default password after first login!
echo [segmentra] You can change it in the UI or via API endpoint.
echo.

:done
echo.
echo [segmentra] All services are starting in separate windows.
echo [segmentra] Check the API and UI windows for status.
echo.
echo [segmentra] To stop all services: Close the API and UI windows, then run:
echo [segmentra]   docker compose down
echo.

endlocal


