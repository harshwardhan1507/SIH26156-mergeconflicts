@echo off
setlocal enabledelayedexpansion
title Stop ULPF Dashboard
color 0C
cd /d "%~dp0"
cls
echo ======================================================================
echo           Universal Log Pre-processing Framework (ULPF)
echo           Stopping Operations Dashboard Server...
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

if defined PYTHON_EXE (
    !PYTHON_EXE! -m ulpf.cli dashboard --stop
    goto :done
)

:: Direct PowerShell fallback
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }; Write-Host '[+] Server on port 8000 stopped.' -ForegroundColor Green"

:done
echo.
pause
