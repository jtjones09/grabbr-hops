# hops installer (Windows). Builds hops and sets it to start at login.
#
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#
# Safe to re-run — it rebuilds and refreshes the install. This is a convenience
# wrapper; you can also just build and run .\target\release\hops.exe yourself
# (see the README "Quick start").

$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot
$bin  = Join-Path $repo 'target\release\hops.exe'

Write-Host '==> Building hops (first build takes a few minutes)...'
Push-Location $repo
cargo build --release --no-default-features --features tui --features slint
Pop-Location
if (-not (Test-Path $bin)) { throw "build did not produce $bin" }

$work = Join-Path $env:USERPROFILE 'hops'
New-Item -ItemType Directory -Force -Path (Join-Path $work 'logs') | Out-Null

# Daemon: a .cmd sets the log + runs it; a .vbs launches that .cmd hidden (no
# console flash). Tray: a .vbs launches `hops gui --hidden`.
Set-Content -Encoding ASCII (Join-Path $work 'hops-daemon.cmd') @"
@echo off
set "HOPS_LOG_LEVEL=info"
"$bin" daemon >> "%USERPROFILE%\hops\logs\daemon.log" 2>&1
"@
Set-Content -Encoding ASCII (Join-Path $work 'hops-daemon.vbs') @"
Set s = CreateObject("WScript.Shell")
s.Run """$work\hops-daemon.cmd""", 0, False
"@
Set-Content -Encoding ASCII (Join-Path $work 'hops-gui.vbs') @"
Set s = CreateObject("WScript.Shell")
s.Run """$bin"" gui --hidden", 0, False
"@

# Autostart at login via the Run key (hidden, no elevation needed).
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Set-ItemProperty -Path $runKey -Name 'hops-daemon' -Value "wscript.exe `"$work\hops-daemon.vbs`""
Set-ItemProperty -Path $runKey -Name 'hops-gui'    -Value "wscript.exe `"$work\hops-gui.vbs`""

# Start them now (so you don't have to log out/in).
taskkill /F /IM hops.exe 2>$null | Out-Null
Start-Process wscript.exe -ArgumentList "`"$work\hops-daemon.vbs`""
Start-Process wscript.exe -ArgumentList "`"$work\hops-gui.vbs`""

Write-Host ''
Write-Host '[OK] hops is running (tray icon in the notification area) and will start at login.'
Write-Host '     If Windows Firewall prompts, allow hops on your PRIVATE network.'
