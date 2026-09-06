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
$scriptsDir = (Get-Location).Path;
$projectRoot = (Resolve-Path (Join-Path $scriptsDir '..')).Path;

# 1. Start Dashboard Shortcut
$startLink = $ws.CreateShortcut([System.IO.Path]::Combine($desktop, 'ULPF Dashboard.lnk'));
$startLink.TargetPath = [System.IO.Path]::Combine($scriptsDir, 'Start_Dashboard_Background.vbs');
$startLink.WorkingDirectory = $projectRoot;
$startLink.Description = 'Universal Log Pre-processing Framework Dashboard (1-Click Background)';
$iconPath = [System.IO.Path]::Combine($projectRoot, 'tools\windows\ulpf_icon.ico');
if (Test-Path $iconPath) {
    $startLink.IconLocation = $iconPath;
}
$startLink.Save();
Write-Host '[SUCCESS] Created Desktop Shortcut: ULPF Dashboard.lnk' -ForegroundColor Green;

# 2. Stop Dashboard Shortcut
$stopLink = $ws.CreateShortcut([System.IO.Path]::Combine($desktop, 'Stop ULPF Dashboard.lnk'));
$stopLink.TargetPath = [System.IO.Path]::Combine($scriptsDir, 'Stop_Dashboard.bat');
$stopLink.WorkingDirectory = $projectRoot;
$stopLink.Description = 'Stop running ULPF Dashboard Background Server';
$stopLink.Save();
Write-Host '[SUCCESS] Created Desktop Shortcut: Stop ULPF Dashboard.lnk' -ForegroundColor Green;
"

echo.
pause
