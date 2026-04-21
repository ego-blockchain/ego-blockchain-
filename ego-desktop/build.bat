@echo off
echo Building Ego Desktop MVP...

:: Check if npm dependencies are installed
if not exist "node_modules" (
    echo Installing npm dependencies...
    npm install
)

:: Build the frontend
echo Building frontend...
npm run build

:: Check if Tauri is available
where cargo-tauri >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing Tauri CLI...
    cargo install tauri-cli
)

:: Build the Tauri application
echo Building Tauri application...
cargo tauri build

echo.
echo Build complete!
echo.
echo The installer can be found in:
echo   src-tauri\target\release\bundle\nsis\
echo.
pause