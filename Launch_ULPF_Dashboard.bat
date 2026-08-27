@echo off
title ULPF Operations Dashboard Launcher
color 0B
cls
echo ======================================================================
echo           Universal Log Pre-processing Framework (ULPF)
echo ======================================================================
echo.
echo [*] Checking Python environment...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in system PATH.
    echo Please install Python 3.11+ from https://www.python.org/
    pause
    exit /b 1
)

echo [*] Initializing sample log ingestion...
python -m ulpf.cli ingest --input ulpf/sample_logs/ --output output/ >nul 2>&1

echo [*] Launching web browser to http://127.0.0.1:8000 ...
start "" "http://127.0.0.1:8000"

echo [*] Starting ULPF Dashboard Server on port 8000...
echo [INFO] Press Ctrl+C in this window to stop the server.
echo.
python -m ulpf.dashboard.app --port 8000 --output-dir output

pause
