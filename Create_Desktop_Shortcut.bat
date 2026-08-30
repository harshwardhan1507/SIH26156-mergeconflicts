@echo off
title Create ULPF Desktop Shortcuts
color 0A
cd /d "%~dp0"
cls
echo ======================================================================
echo           Creating ULPF Desktop Shortcuts...
echo ======================================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "
$ws = New-Object -ComObject WScript.Shell;
$desktop = [System.Environment]::GetFolderPath('Desktop');
$root = (Get-Location).Path;

# 1. Start Dashboard Shortcut
$startLink = $ws.CreateShortcut([System.IO.Path]::Combine($desktop, 'ULPF Dashboard.lnk'));
$startLink.TargetPath = [System.IO.Path]::Combine($root, 'Start_Dashboard_Background.vbs');
$startLink.WorkingDirectory = $root;
$startLink.Description = 'Universal Log Pre-processing Framework Dashboard (1-Click Background)';
if (Test-Path ([System.IO.Path]::Combine($root, 'packaging\windows\ulpf_icon.ico'))) {
    $startLink.IconLocation = [System.IO.Path]::Combine($root, 'packaging\windows\ulpf_icon.ico');
}
$startLink.Save();
Write-Host '[SUCCESS] Created Desktop Shortcut: ULPF Dashboard.lnk' -ForegroundColor Green;

# 2. Stop Dashboard Shortcut
$stopLink = $ws.CreateShortcut([System.IO.Path]::Combine($desktop, 'Stop ULPF Dashboard.lnk'));
$stopLink.TargetPath = [System.IO.Path]::Combine($root, 'Stop_Dashboard.bat');
$stopLink.WorkingDirectory = $root;
$stopLink.Description = 'Stop running ULPF Dashboard Background Server';
$stopLink.Save();
Write-Host '[SUCCESS] Created Desktop Shortcut: Stop ULPF Dashboard.lnk' -ForegroundColor Green;
"

echo.
pause
