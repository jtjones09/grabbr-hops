@echo off
rem grabbr-hop - DEV / TEST.
rem
rem Builds the working tree, checks the build matches the source, and only then
rem restarts the daemon and tray on it. Your DAILY binary is untouched.
rem
rem Runs in a VISIBLE console on purpose. This used to be a .vbs that launched
rem everything with window style 0 and did not build at all - so a "deployment"
rem silently relaunched the previous day's binary, and a failed build showed
rem nothing whatsoever. A check whose failure is invisible reads as success.
setlocal
call "%~dp0grabbr-hop-paths.cmd"

rem Windows locks a running executable, so the linker cannot replace hops.exe
rem while the daemon or tray is using it. Renaming works where deleting does
rem not: the running process keeps running from the renamed file and cargo
rem writes a fresh one. NOT a stop-first: stopping before the build would take
rem your keyboard and mouse away for the whole build, and leave them gone if
rem the build then failed.
if exist "%HOPS_RAW%" (
  del /f /q "%HOPS_RAW%.old" >nul 2>&1
  ren "%HOPS_RAW%" "hops.exe.old" >nul 2>&1
)

echo Building the dev build...
echo   (the first build after a toolchain change downloads a compiler - several
echo    minutes, and not a hang)
pushd "%HOPS_REPO%" || goto :norepo
cargo build --release --no-default-features --features "tui slint"
set "RC=%ERRORLEVEL%"
popd
if not "%RC%"=="0" goto :buildfailed
if not exist "%HOPS_RAW%" goto :nobinary

rem Does this binary even have the check? One built before the check existed
rem makes clap exit 2 for an unknown subcommand - the same code used below for
rem "stale". The verdict would be right by accident, the message useless.
"%HOPS_RAW%" build-check --help >nul 2>&1
if not "%ERRORLEVEL%"=="0" goto :tooold

rem Does the binary cargo just linked match the source? Before anything is
rem stopped: an abort here leaves whatever is running exactly as it was.
"%HOPS_RAW%" build-check --repo "%HOPS_REPO%" --strict
set "RC=%ERRORLEVEL%"
if "%RC%"=="2" goto :stale
if "%RC%"=="3" goto :cannotverify
if not "%RC%"=="0" goto :noverdict

echo.
echo Switching the daemon and tray onto the new build...
rem Through hops-ctl, which stops each role BY PID. `taskkill /f /im hops.exe`
rem cannot tell the daemon from the tray - they are the same image - so it took
rem both every time, and needed an elevated session to do it.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hops-ctl.ps1" stop-gui
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hops-ctl.ps1" stop-daemon
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hops-ctl.ps1" start-daemon -DaemonCmd "%~dp0grabbr-hop-daemon-dev.cmd"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hops-ctl.ps1" start-gui -Bin "%HOPS_RAW%"
del /f /q "%HOPS_RAW%.old" >nul 2>&1
echo.
"%HOPS_RAW%" --version
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hops-ctl.ps1" status
echo.
echo   Logs: %LOCALAPPDATA%\hops\logs\
echo   Restart just the tray later, without stopping the daemon: restart-tray.cmd
timeout /t 8 >nul 2>&1
exit /b 0

:stale
echo.
echo   STALE - not switching. Nothing was stopped.
echo   The build above does not match %HOPS_REPO%.
goto :hold
:cannotverify
echo.
echo   CANNOT VERIFY - nothing was compared, so this is NOT a clean bill of
echo   health. Check %HOPS_REPO% is a git checkout and git is on PATH.
echo   Nothing was stopped.
goto :hold
:noverdict
echo.
echo   build-check gave no verdict (exit %RC%). That is the check failing to
echo   run, not a statement about the binary. Nothing was stopped.
goto :hold
:tooold
echo.
echo   This binary predates the build check, so it cannot be compared. The
echo   build above should have produced a newer one; if you see this, cargo did
echo   not rebuild. Nothing was stopped.
goto :hold
:norepo
echo.
echo   No repo at %HOPS_REPO% - edit grabbr-hop-paths.cmd.
goto :hold
:buildfailed
echo.
echo   Build failed (exit %RC%). Nothing was stopped; the previous dev binary
echo   is back in place. Compiler errors are above.
goto :hold
:nobinary
echo.
echo   The build reported success but there is no binary at %HOPS_RAW%.
echo   If CARGO_TARGET_DIR is set, cargo wrote it somewhere else.
echo   Nothing was stopped.
goto :hold

:hold
rem Every abort lands here, so the restore lives here rather than in each branch
rem where one could be forgotten: if the build produced nothing, put the
rem previous binary back so a failure leaves the machine as it was.
if not exist "%HOPS_RAW%" if exist "%HOPS_RAW%.old" ren "%HOPS_RAW%.old" "hops.exe" >nul 2>&1
echo.
pause
exit /b 1
