@echo off
rem Brings the dev checkout at HOPS_REPO up to date before a dev build.
rem Exits 0 to build, 1 to stop having built nothing. Called by
rem grabbr-hop-dev.cmd, which sets HOPS_REPO; tested on Windows CI by
rem tests/launcher_update_windows.rs.
setlocal
rem Bring the checkout up to date before building, so what gets built is what
rem the remote branch holds, not whatever was last pulled on this machine. It
rem only ever fast-forwards. It builds what is there, and says why, when the
rem tree has uncommitted changes, the branch tracks no remote branch, the remote
rem cannot be reached, or HOPS_NO_PULL is set. It stops, having built nothing,
rem when the branch has diverged from its remote branch.
if defined HOPS_NO_PULL (
  echo   HOPS_NO_PULL is set: building the checkout as it is.
  goto :updated
)
pushd "%HOPS_REPO%" || goto :norepo
set "HOPS_BRANCH="
for /f "delims=" %%b in ('git symbolic-ref --short -q HEAD 2^>nul') do set "HOPS_BRANCH=%%b"
if not defined HOPS_BRANCH (
  echo   The checkout is not on a branch: building it as it is.
  popd
  goto :updated
)
set "HOPS_DIRTY="
for /f "delims=" %%s in ('git status --porcelain --untracked-files^=no') do set "HOPS_DIRTY=1"
if defined HOPS_DIRTY (
  echo   %HOPS_BRANCH% has uncommitted changes: building them without pulling.
  popd
  goto :updated
)
git rev-parse -q --verify "@{upstream}" >nul 2>&1
if errorlevel 1 (
  echo   %HOPS_BRANCH% tracks no remote branch: building it as it is.
  popd
  goto :updated
)
git fetch --quiet
if errorlevel 1 (
  echo   Could not reach the remote: building %HOPS_BRANCH% as it is.
  popd
  goto :updated
)
git merge --ff-only --quiet "@{upstream}" >nul 2>&1
if errorlevel 1 (
  popd
  goto :diverged
)
for /f "delims=" %%l in ('git log --oneline -1') do echo   Building %HOPS_BRANCH% at %%l
popd
:updated
exit /b 0

rem Only reached by goto: each ends the update without building.
:diverged
echo.
echo   %HOPS_BRANCH% has diverged from its remote branch, so nothing was built.
echo   Sort it out in %HOPS_REPO%, or run again with HOPS_NO_PULL=1 set.
exit /b 1

:norepo
echo.
echo   No repo at %HOPS_REPO% - edit grabbr-hop-paths.cmd.
exit /b 1
