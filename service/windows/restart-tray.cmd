@echo off
rem Restart ONLY the tray. The daemon keeps running, so input keeps working
rem while the icon comes back. Run from your own desktop session - a tray
rem started from an SSH session lands elsewhere and never appears.
call "%~dp0grabbr-hop-paths.cmd" 2>nul
if not defined HOPS_RAW set "HOPS_RAW=D:\LocalRepos\grabbr-hop\target\release\hops.exe"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hops-ctl.ps1" restart-gui -Bin "%HOPS_RAW%"
echo.
pause
