@echo off
setlocal enabledelayedexpansion
title ULPF Operations Dashboard Launcher
color 0B
cd /d "%~dp0"
cls
echo ======================================================================
echo           Universal Log Pre-processing Framework (ULPF)
echo           Operations Dashboard Launcher ^& Manager
echo ======================================================================
echo.

:: Detect Python
set "PYTHON_EXE="
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 set "PYTHON_EXE=python"
if not defined PYTHON_EXE (
    where py >nul 2>&1
    if !ERRORLEVEL! EQU 0 set "PYTHON_EXE=py"
)
if not defined PYTHON_EXE (
    if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" (
        set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
        set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
        set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    )
)

if not defined PYTHON_EXE (
    echo [ERROR] Python was not found in your system.
    echo Please install Python 3.11+ from https://www.python.org/
    echo and ensure 'Add Python to PATH' is checked.
    echo.
    pause
    exit /b 1
)

echo [*] Python environment: !PYTHON_EXE!
echo.

:: Check if dashboard is already running
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/stats' -TimeoutSec 1 -UseBasicParsing -ErrorAction Stop; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo ======================================================================
    echo   [+] ULPF Operations Dashboard is ALREADY ACTIVE at:
    echo       http://127.0.0.1:8000
    echo ======================================================================
    echo.
    echo Opening dashboard in your default browser...
    start http://127.0.0.1:8000
    echo.
    echo Options:
    echo   [1] Leave server running in background and Exit (Default)
    echo   [2] Stop / Shutdown the running Dashboard Server
    echo.
    set /p "CHOICE=Select an option [1-2] (default: 1): "
    if "!CHOICE!"=="2" (
        echo.
        !PYTHON_EXE! -m ulpf.cli dashboard --stop
        pause
    )
    exit /b 0
)

echo Starting ULPF Operations Dashboard in Persistent Background Mode...
echo [INFO] Dashboard will open in your browser at http://127.0.0.1:8000
echo [INFO] Closing this window will NOT stop the dashboard server.
echo [INFO] To stop the server at any time, run Stop_Dashboard.bat
echo.

!PYTHON_EXE! -m ulpf.cli dashboard --background --port 8000 --output-dir output

echo.
echo ======================================================================
echo   Dashboard is running! You can safely close this window.
echo ======================================================================
echo.
timeout /t 5 >nul
