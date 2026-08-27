@echo off
setlocal enabledelayedexpansion
title ULPF Master Test Runner (VPN, Cloud, MySQL, Windows, OS)

:: Change to current directory
cd /d "%~dp0"

echo ===============================================================================
echo   UNIVERSAL LOG PRE-PROCESSING FRAMEWORK (ULPF)
echo   Master 1-Click Test ^& System Verification Suite
echo ===============================================================================
echo.

:: Detect Python executable
set "PYTHON_EXE="

:: Check default python in PATH
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PYTHON_EXE=python"
)

:: Check py launcher if python not found
if "!PYTHON_EXE!"=="" (
    where py >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "PYTHON_EXE=py"
    )
)

:: Check standard Windows user Python path
if "!PYTHON_EXE!"=="" (
    if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" (
        set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
        set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    ) else if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
        set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    )
)

if "!PYTHON_EXE!"=="" (
    echo [ERROR] Python was not found in PATH or standard directories.
    echo Please install Python 3.11+ and ensure 'Add Python to PATH' is checked.
    echo.
    pause
    exit /b 1
)

echo [INFO] Using Python: !PYTHON_EXE!
echo [INFO] Running full end-to-end audit (VPN, Cloud, MySQL, OS, Sockets, Pytest)...
echo.

:: Execute Master Test Suite
!PYTHON_EXE! test_all.py

echo.
echo ===============================================================================
echo   Test run finished. Press any key to close this window.
echo ===============================================================================
pause >nul
