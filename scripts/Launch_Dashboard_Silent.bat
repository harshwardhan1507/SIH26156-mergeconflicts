@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0\.."

:: Detect Python executable
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
    !PYTHON_EXE! -m ulpf.cli dashboard --background --output-dir output
)
