@echo off
title Create ULPF Desktop Shortcut
color 0A
cls
echo ======================================================================
echo           Creating ULPF Desktop Shortcut...
echo ======================================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), 'ULPF Dashboard.lnk')); $s.TargetPath = [System.IO.Path]::Combine((Get-Location).Path, 'Launch_ULPF_Dashboard.bat'); $s.WorkingDirectory = (Get-Location).Path; $s.Description = 'Universal Log Pre-processing Framework Dashboard'; $s.Save(); Write-Host '[SUCCESS] Shortcut created on your Desktop: ULPF Dashboard.lnk' -ForegroundColor Green"

echo.
pause
