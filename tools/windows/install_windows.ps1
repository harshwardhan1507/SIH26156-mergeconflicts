# ULPF Windows Automated Installer
# Usage: powershell -ExecutionPolicy Bypass -File install_windows.ps1
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Universal Log Pre-processing Framework (ULPF) Installer " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Find local wheel in current folder or download
$wheel = Get-ChildItem -Filter "ulpf-*.whl" | Select-Object -First 1
if ($wheel) {
    Write-Host "Installing from local wheel: $($wheel.Name)..." -ForegroundColor Yellow
    python -m pip install --upgrade --no-index --find-links . $wheel.FullName
} else {
    Write-Host "Installing via pip from source..." -ForegroundColor Yellow
    python -m pip install ulpf
}

Write-Host "`nVerifying ULPF CLI..." -ForegroundColor Green
python -m ulpf.cli list-parsers

Write-Host "`nInstallation Successful!" -ForegroundColor Green
Write-Host "To start the dashboard: python -m ulpf.dashboard.app --port 8000" -ForegroundColor Cyan
Write-Host "To ingest logs:         python -m ulpf.cli ingest --input <log-folder>" -ForegroundColor Cyan
