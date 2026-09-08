@echo off
rem internal - CALLed by the other launchers to set shared paths.
rem
rem One place for these. The repo path used to live in both the dev launcher
rem and the daemon .cmd; editing one and missing the other does not fail
rem loudly, it builds one binary and starts a different one - which is the
rem failure the build-check gate exists to catch.
rem
rem `if not defined` so an already-set value wins: that is how these can be
rem pointed at a scratch tree to check the failure paths without a real repo.
if not defined HOPS_REPO   set "HOPS_REPO=D:\LocalRepos\grabbr-hop"
if not defined HOPS_LAUNCH set "HOPS_LAUNCH=%USERPROFILE%\grabbr-hop"
set "HOPS_RAW=%HOPS_REPO%\target\release\hops.exe"
set "HOPS_DAILY=%HOPS_LAUNCH%\hops.exe"
