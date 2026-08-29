@echo off
setlocal enabledelayedexpansion
title ULPF Operations Dashboard Launcher
color 0B
cls
echo ======================================================================
echo           Universal Log Pre-processing Framework (ULPF)
echo           1-Click Operations Dashboard Launcher
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
    echo [ERROR] Python was not found in your PATH.
    echo Please install Python 3.11+ from https://www.python.org/
    pause
    exit /b 1
)

echo [*] Python environment detected: !PYTHON_EXE!
echo [*] Starting ULPF Operations Dashboard...
echo [INFO] Dashboard will open automatically in your browser (http://127.0.0.1:8000).
echo [INFO] Press Ctrl+C in this window to stop the server.
echo.
!PYTHON_EXE! -m ulpf.cli dashboard --port 8000 --output-dir output

pause
