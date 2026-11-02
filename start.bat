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
REM Docker Desktop can be running while docker.exe is not on this window's PATH.
where docker >nul 2>&1
if not errorlevel 1 goto docker_on_path
if exist "%ProgramFiles%\Docker\Docker\resources\bin\docker.exe" goto docker_add_path
goto docker_on_path
:docker_add_path
set "PATH=%ProgramFiles%\Docker\Docker\resources\bin;%PATH%"
echo [segmentra] docker was not on PATH; using the Docker Desktop folder for this run.
:docker_on_path
set "DOCKER_ERR=%TEMP%\segmentra-docker-check.txt"
docker version --format "{{.Server.Os}}" >nul 2>"%DOCKER_ERR%"
if not errorlevel 1 goto docker_ok
echo [segmentra] ERROR: cannot use Docker. Check that Docker Desktop shows "Engine running".
echo [segmentra] Docker says:
type "%DOCKER_ERR%"
del "%DOCKER_ERR%" >nul 2>&1
exit /b 1
:docker_ok
del "%DOCKER_ERR%" >nul 2>&1
echo [segmentra] Docker check passed
echo.

REM The production stack uses the same ports as the API started below.
for /f "delims=" %%C in ('docker compose ps -q segmentra-app 2^>nul') do goto prod_running
goto prod_not_running
:prod_running
echo [segmentra] ERROR: the production stack is running and uses the same ports.
echo [segmentra] Stop it first: docker compose stop
exit /b 1
:prod_not_running

REM Check Node.js and npm
where node >nul 2>&1
if not errorlevel 1 goto node_found
echo [segmentra] ERROR: Node.js was not found. Install Node.js 20+ from https://nodejs.org
exit /b 1
:node_found
node -e "process.exit(Number(process.versions.node.split('.')[0])>=20?0:1)"
if not errorlevel 1 goto node_ok
echo [segmentra] ERROR: Node.js 20+ is required. Install it from https://nodejs.org
node -v
exit /b 1
:node_ok
echo [segmentra] Node.js check passed
echo.

REM Install / refresh dependencies:
REM  - clean install (npm ci) when node_modules is missing
REM  - npm install when package-lock.json or any package.json is newer than the last install
if not exist node_modules\.package-lock.json goto deps_clean_install
node -e "const fs=require('fs');const t=f=>{try{return fs.statSync(f).mtimeMs}catch{return 0}};const m=t('node_modules/.package-lock.json');const ws=d=>fs.readdirSync(d).map(x=>d+'/'+x+'/package.json');const files=['package-lock.json','package.json'].concat(ws('apps'),ws('packages'));process.exit(files.some(f=>t(f)>m)?1:0)"
if not errorlevel 1 goto deps_done
echo [segmentra] Dependency manifests changed - running npm install...
call npm install
if errorlevel 1 goto deps_failed
echo [segmentra] Dependencies updated - OK
echo.
goto deps_done
:deps_clean_install
echo [segmentra] Installing dependencies (npm ci)...
if exist package-lock.json (call npm ci) else (call npm install)
if errorlevel 1 goto deps_failed
echo [segmentra] Dependencies installed - OK
echo.
goto deps_done
:deps_failed
echo [segmentra] ERROR: Failed to install dependencies
exit /b 1
:deps_done

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
docker compose exec -T segmentra-db pg_isready -U segmentra >nul 2>&1
if errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto :wait_db
)
echo [segmentra] PostgreSQL is ready - OK
echo.

REM Set up environment variables
REM SEGMENTRA_DATABASE_URL if provided, otherwise the local compose DB, whose password
REM may come from a production install's .env.
for /f "delims=" %%U in ('node packages\db\scripts\dev-env.js database-url') do set "DATABASE_URL=%%U"
if not "%SEGMENTRA_KEK_B64%"=="" goto kek_done
for /f "delims=" %%K in ('node packages\db\scripts\dev-env.js get SEGMENTRA_KEK_B64') do set "SEGMENTRA_KEK_B64=%%K"
:kek_done

REM JWT secret: prod requires an explicit JWT_SECRET; dev generates a random one once
REM and keeps it in the untracked file .dev-jwt-secret.
if /I "%MODE%"=="prod" goto jwt_prod
if not "%JWT_SECRET%"=="" goto jwt_done
if exist .dev-jwt-secret goto jwt_load
node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))" > .dev-jwt-secret
echo [segmentra] Generated development JWT secret in .dev-jwt-secret
:jwt_load
set /p JWT_SECRET=<.dev-jwt-secret
goto jwt_done
:jwt_prod
set "NODE_ENV=production"
if not "%JWT_SECRET%"=="" goto jwt_done
echo [segmentra] ERROR: JWT_SECRET must be set in prod mode (at least 32 random characters).
exit /b 1
:jwt_done

REM Set optional environment variables with defaults
if "%PORT%"=="" set "PORT=8080"
if "%BUNDLES_DIR%"=="" set "BUNDLES_DIR=./data/bundles"
if "%ANSIBLE_RUNNER_CONTAINER%"=="" set "ANSIBLE_RUNNER_CONTAINER=segmentra-ansible-runner"

echo [segmentra] Configuration:
echo [segmentra]   PORT=%PORT%
echo [segmentra]   MODE=%MODE%
echo.

REM Run migrations
echo [segmentra] Running database migrations...
node packages\db\scripts\dev-env.js check-db
if errorlevel 1 exit /b 1
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
call npm run build
if errorlevel 1 (
    echo [segmentra] ERROR: Build failed
    exit /b 1
)
echo [segmentra] Build complete - OK
echo.

REM Launch API in new window with all environment variables
echo [segmentra] Launching API (new window)...
REM The new window inherits this environment, so the variables need no quoting games.
start "Segmentra API" /D "%~dp0." cmd /k "echo [API] Starting on port %PORT%... && npm run dev -w apps/api"

REM Launch UI in new window
echo [segmentra] Launching UI (new window)...
start "Segmentra UI" /D "%~dp0apps\web" cmd /k "echo [UI] Starting Vite dev server... && npm run dev"

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
if not "%SEGMENTRA_ADMIN_PASSWORD%"=="" goto admin_from_env
if /I "%MODE%"=="prod" goto admin_prod
echo [segmentra] Password: admin123 - dev default, unless the admin user already existed
echo.
echo [segmentra] IMPORTANT: Change the default password after first login!
goto admin_done
:admin_prod
echo [segmentra] Password: none created by default in prod mode; set SEGMENTRA_ADMIN_PASSWORD before the first start
goto admin_done
:admin_from_env
echo [segmentra] Password: value of SEGMENTRA_ADMIN_PASSWORD when the admin user was first created
:admin_done
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


