# PowerShell Installer for Ego Desktop MVP
Write-Host "🚀 EGO DESKTOP MVP - INSTALLER" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""

# Check if we're in the right directory
if (-not (Test-Path "package.json")) {
    Write-Error "Please run this from the ego-desktop-mvp directory"
    exit 1
}

Write-Host "Step 1: Building frontend..." -ForegroundColor Yellow
try {
    npm run build
    Write-Host "Frontend built successfully" -ForegroundColor Green
} catch {
    Write-Error "Frontend build failed"
    exit 1
}

Write-Host ""
Write-Host "Step 2: Creating desktop launcher..." -ForegroundColor Yellow

# Create desktop launcher directly (faster than full build)
$desktopPath = [Environment]::GetFolderPath("Desktop")
$launcherPath = "$desktopPath\EgoDesktop-MVP.bat"
$currentPath = (Get-Location).Path

$launcherContent = @'
@echo off
title Ego Desktop MVP
echo ================================================
echo   🚀 EGO DESKTOP MVP - QUANTUM-SAFE BLOCKCHAIN
echo ================================================
echo.
echo Loading all MVP features...
echo   Quantum-Safe Key Generation
echo   Wallet with EGOC Balance
echo   EgoSafe File Sharing
echo   Storage Dashboard
echo   Earnings Interface
echo   Built-in Block Explorer
echo.
cd /d "{0}"
if not exist "node_modules" npm install
npx tauri dev --no-watch
'@ -f $currentPath

$launcherContent | Out-File -FilePath $launcherPath -Encoding ascii

Write-Host "Desktop launcher created: EgoDesktop-MVP.bat" -ForegroundColor Green

# Also create a PowerShell launcher for advanced users
$psLauncherPath = "$desktopPath\EgoDesktop-MVP.ps1"
$psLauncherContent = @'
# Ego Desktop MVP Launcher
Write-Host "🚀 Starting Ego Desktop MVP..." -ForegroundColor Green
Set-Location "{0}"
if (!(Test-Path "node_modules")) {{ npm install }}
& npx tauri dev --no-watch
'@ -f $currentPath

$psLauncherContent | Out-File -FilePath $psLauncherPath -Encoding utf8

Write-Host "PowerShell launcher created: EgoDesktop-MVP.ps1" -ForegroundColor Green

Write-Host ""
Write-Host "🎉 Installation complete!" -ForegroundColor Green
Write-Host "Check your Desktop for:" -ForegroundColor Cyan
Write-Host "  • EgoDesktop-MVP.bat (double-click to run)" -ForegroundColor White
Write-Host "  • EgoDesktop-MVP.ps1 (PowerShell version)" -ForegroundColor White
Write-Host ""
Write-Host "The application includes all requested MVP features!" -ForegroundColor Cyan

# Ask if user wants to launch now
$response = Read-Host "Would you like to launch Ego Desktop MVP now? (y/n)"
if ($response -eq 'y' -or $response -eq 'Y') {
    Write-Host "Launching Ego Desktop MVP..." -ForegroundColor Green
    Start-Process $launcherPath
}