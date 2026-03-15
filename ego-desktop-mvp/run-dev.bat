@echo off
title Ego Desktop MVP - Development Mode
echo.
echo ================================================
echo   🚀 EGO DESKTOP MVP - QUANTUM-SAFE BLOCKCHAIN
echo ================================================
echo.
echo Starting in development mode...
echo This will open a desktop window with all MVP features!
echo.
echo Available Features:
echo  ✅ Quantum-Safe Key Generation (Dilithium-2 + Kyber-768)
echo  ✅ 24-Word Recovery Phrase with QR Codes
echo  ✅ Wallet Balance Display (EGOC/uEGOC)
echo  ✅ System Tray Integration
echo  ✅ Coverage Simulation
echo  ✅ Storage Metrics Dashboard
echo  ✅ Earnings and Staking Interface
echo  ✅ Built-in Block Explorer
echo.
echo Press Ctrl+C to stop
echo.

cd /d "%~dp0"
if exist "node_modules" (
    echo Starting Tauri development server...
    npx tauri dev --no-watch
) else (
    echo Installing dependencies first...
    npm install
    echo Starting application...
    npx tauri dev --no-watch
)