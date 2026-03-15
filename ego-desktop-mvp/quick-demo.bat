@echo off
title Ego Desktop MVP - Quick Demo
echo.
echo ================================================
echo   🚀 EGO DESKTOP MVP - QUANTUM-SAFE BLOCKCHAIN
echo ================================================
echo.
echo QUICK DEMO VERSION - Ready to use!
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
echo  ✅ EgoSafe Secure File Sharing
echo.
echo This opens the desktop application with all MVP features
echo running in demo mode with simulated blockchain data.
echo.
echo Press Ctrl+C to stop the application
echo.

cd /d "%~dp0"
if not exist "node_modules" (
    echo Installing dependencies...
    npm install
)
echo.
echo Starting Ego Desktop MVP...
npx tauri dev --no-watch