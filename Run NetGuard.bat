@echo off
cd /d "%~dp0"
echo Starting NetGuard...
start "NetGuard Server" python web.py
timeout /t 2 /nobreak >nul
start "" "http://localhost:5000"
echo NetGuard is running. Close the server window to stop.
pause
