# Build ULPF Windows Executables (.exe)
$ErrorActionPreference = "Stop"
Write-Host "Building ULPF Executables..." -ForegroundColor Cyan
python packaging\windows\build_exe.py
