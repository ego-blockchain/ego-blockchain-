# PowerShell build script for Ego Desktop MVP
Write-Host "Building Ego Desktop MVP..." -ForegroundColor Green

# Check if we're in the right directory
if (-not (Test-Path "package.json")) {
    Write-Error "Please run this from the ego-desktop-mvp directory"
    exit 1
}

# Build frontend if not already built
if (-not (Test-Path "dist")) {
    Write-Host "Building frontend..." -ForegroundColor Yellow
    npm run build
}

# Try to build with Tauri
Write-Host "Building Tauri application..." -ForegroundColor Yellow
try {
    npx tauri build
    Write-Host "Build successful! Check src-tauri\target\release\bundle\ for installer" -ForegroundColor Green
} catch {
    Write-Host "Full build failed. Creating development setup instead..." -ForegroundColor Yellow

    # Create a simple executable launcher instead
    Write-Host "Creating launcher script..." -ForegroundColor Cyan
    @"
@echo off
echo Starting Ego Desktop MVP...
cd /d "%~dp0"
if exist "npx" (
    npx tauri dev
) else (
    echo Please install Node.js and npm first
    pause
)
"@ | Out-File -FilePath "EgoDesktop-Launcher.bat" -Encoding ascii

    Write-Host "Created EgoDesktop-Launcher.bat - double-click to run the app!" -ForegroundColor Green
}

Write-Host "Build process complete!" -ForegroundColor Green