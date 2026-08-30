@echo off
setlocal enabledelayedexpansion
title ULPF Operations Center Dashboard

cd /d "%~dp0"

echo ===============================================================================
echo   UNIVERSAL LOG PRE-PROCESSING FRAMEWORK (ULPF)
echo   Operations Dashboard Launcher
echo ===============================================================================
echo.

:: Detect Python
set "PYTHON_EXE=python"
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    where py >nul 2>&1
    if !ERRORLEVEL! EQU 0 set "PYTHON_EXE=py"
)

:: Rebuild index cache if output exists
if exist "output\events.ndjson" (
    echo [INFO] Ingested events detected in output directory.
) else (
    echo [INFO] Ingesting initial baseline sample logs from ulpf/sample_logs...
    !PYTHON_EXE! -m ulpf.cli ingest --input ulpf/sample_logs --output output
)

echo [INFO] Launching ULPF Operations Dashboard in persistent background mode...
!PYTHON_EXE! -m ulpf.cli dashboard --background --port 8000 --output-dir output

echo.
echo [INFO] Server is active at http://127.0.0.1:8000
echo [INFO] You can safely close this window. To stop the server, run Stop_Dashboard.bat
timeout /t 5 >nul
