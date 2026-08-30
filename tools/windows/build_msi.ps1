# Builds ULPF Windows MSI Installer using WiX Toolset v4/v7
param(
    [string]$Version = "1.1.0"
)

$ErrorActionPreference = "Stop"
Write-Host "=== Building ULPF Windows MSI Package v$Version ===" -ForegroundColor Cyan

$rootDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $rootDir

$distPath = Join-Path $rootDir "dist"
if (-not (Test-Path $distPath)) {
    New-Item -ItemType Directory -Path $distPath | Out-Null
}

# 1. Locate WiX Toolset executable
$wixExe = "$env:USERPROFILE\.dotnet\tools\wix.exe"
if (-not (Test-Path $wixExe)) {
    $cmd = Get-Command "wix.exe" -ErrorAction SilentlyContinue
    if ($cmd) {
        $wixExe = $cmd.Source
    }
}

if (-not (Test-Path $wixExe)) {
    Write-Host "[!] WiX toolset not detected. Attempting automatic installation via dotnet..." -ForegroundColor Yellow
    dotnet tool install --global wix
}

if (Test-Path $wixExe) {
    Write-Host "[*] Using WiX executable: $wixExe" -ForegroundColor Green
    $wxsPath = Join-Path $rootDir "packaging\windows\ulpf.wxs"
    $msiOut = Join-Path $distPath "ULPF-$Version-windows-x64.msi"

    Write-Host "[*] Compiling MSI installer package..." -ForegroundColor Yellow
    & $wixExe build $wxsPath -o $msiOut
    if ($LASTEXITCODE -eq 0 -and (Test-Path $msiOut)) {
        $msiSize = (Get-Item $msiOut).Length / 1MB
        Write-Host "============================================================" -ForegroundColor Green
        Write-Host "  MSI INSTALLER CREATED: $msiOut ($([math]::Round($msiSize, 2)) MB)" -ForegroundColor Green
        Write-Host "============================================================" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] WiX build failed with exit code $LASTEXITCODE" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[ERROR] WiX could not be located. Please run 'dotnet tool install --global wix'" -ForegroundColor Red
    exit 1
}
