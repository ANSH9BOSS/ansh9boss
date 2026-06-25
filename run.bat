@echo off
title ANSH9BOSS - Auto Installer & Runner
echo =============================================
echo    ANSH9BOSS - AUTO INSTALLER AND RUNNER       
echo =============================================

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Python is not installed or not in PATH.
    echo [+] Opening Python download page...
    start https://www.python.org/downloads/
    echo Please install Python (ensure you check "Add Python to PATH") and restart this script.
    pause
    exit /b 1
)

:: Install dependencies
echo [*] Installing Python dependencies (rich, pyfiglet)...
python -m pip install rich pyfiglet

:: Run the script
if exist ansh9boss.py (
    python ansh9boss.py %*
) else (
    echo [*] Downloading latest ansh9boss.py from GitHub...
    powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/ANSH9BOSS/ansh9boss/main/ansh9boss.py' -OutFile 'ansh9boss.py'"
    python ansh9boss.py %*
)
pause
