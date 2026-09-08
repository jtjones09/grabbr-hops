@echo off
rem grabbr-hop DEV daemon (started hidden by hops-ctl).
rem
rem The repo path comes from grabbr-hop-paths.cmd rather than being repeated
rem here. It used to be hardcoded in this file AND in the dev launcher, so
rem editing one and missing the other started a different binary than the one
rem that was just built and checked.
call "%~dp0grabbr-hop-paths.cmd"
rem hops opens its own log now (%LOCALAPPDATA%\hops\logs\) whatever starts it,
rem so no redirection here. This level applies to hops' own crates; a
rem dependency stays at warn unless named, e.g. "info,mdns_sd=debug".
set "HOPS_LOG_LEVEL=debug"
set "HOPS_COALESCE_MOTION=1"
"%HOPS_RAW%" daemon
