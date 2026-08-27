# Builds ULPF Windows MSI Installer using WiX Toolset or creates standalone installer package
param(
    [string]$Version = "1.1.0",
    [string]$OutputDir = "dist"
)

$ErrorActionPreference = "Stop"
Write-Host "=== Building ULPF Windows Package v$Version ===" -ForegroundColor Cyan

$distPath = Join-Path $PSScriptRoot "..\..\dist"
if (-not (Test-Path $distPath)) {
    New-Item -ItemType Directory -Path $distPath | Out-Null
}

# 1. Build Python wheel first
Write-Host "[1/3] Building Python Wheel..." -ForegroundColor Yellow
python -m pip wheel . --no-deps -w $distPath

# 2. Check for WiX Toolset
$wixFound = $false
if (Get-Command "candle.exe" -ErrorAction SilentlyContinue) {
    Write-Host "[2/3] WiX Toolset detected. Compiling MSI..." -ForegroundColor Green
    $wxsPath = Join-Path $PSScriptRoot "ulpf.wxs"
    $wixObj = Join-Path $distPath "ulpf.wixobj"
    $msiOut = Join-Path $distPath "ULPF-$Version-windows-x64.msi"
    
    & candle.exe -out $wixObj $wxsPath
    & light.exe -ext WixUIExtension -out $msiOut $wixObj
    Write-Host "MSI Created: $msiOut" -ForegroundColor Green
    $wixFound = $true
} else {
    Write-Host "[2/3] WiX Toolset not installed locally. Generating MSI bundle wrapper..." -ForegroundColor Yellow
}

# 3. Create Windows Portable & Installer Zip Bundle
Write-Host "[3/3] Creating Windows Release Archive..." -ForegroundColor Yellow
$bundleName = "ULPF-$Version-windows-x64"
$bundleDir = Join-Path $distPath $bundleName
if (Test-Path $bundleDir) { Remove-Item -Recurse -Force $bundleDir }
New-Item -ItemType Directory -Path $bundleDir | Out-Null

Copy-Item -Path "packaging\windows\install_windows.ps1" -Destination $bundleDir
Copy-Item -Path "$distPath\ulpf-$Version-py3-none-any.whl" -Destination $bundleDir
Copy-Item -Path "README.md" -Destination $bundleDir
Copy-Item -Path "LICENSE" -Destination $bundleDir

$zipOut = Join-Path $distPath "$bundleName.zip"
if (Test-Path $zipOut) { Remove-Item -Force $zipOut }
Compress-Archive -Path "$bundleDir\*" -DestinationPath $zipOut
Write-Host "Windows Release Archive created: $zipOut" -ForegroundColor Green
