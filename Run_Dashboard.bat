@echo off
setlocal enabledelayedexpansion
title ULPF Operations Center Dashboard

cd /d "%~dp0"

echo ===============================================================================
echo   UNIVERSAL LOG PRE-PROCESSING FRAMEWORK (ULPF)
echo   1-Click Dashboard Server Launcher
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
    echo [INFO] Ingesting initial baseline sample logs...
    !PYTHON_EXE! -m ulpf.cli ingest --input sample_logs --output output
)

echo [INFO] Opening web browser at http://127.0.0.1:8000 ...
start http://127.0.0.1:8000

echo [INFO] Starting FastAPI server on port 8000...
!PYTHON_EXE! -m ulpf.cli dashboard --port 8000 --output-dir output

pause
