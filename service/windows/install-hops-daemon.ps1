# install-hops-daemon.ps1 — run the hops daemon headless at logon on Windows.
#
# Why a Scheduled Task and not a Windows *service*: a service runs in session 0,
# which is isolated from the interactive desktop, so it cannot inject keyboard /
# mouse input into your session (Windows UIPI / session-0 isolation). A logon
# Scheduled Task runs hops IN your interactive session, which is what input
# emulation needs. RunLevel Highest lets it inject into elevated windows too.
#
# Usage (from an elevated PowerShell — right-click → Run as administrator):
#   .\install-hops-daemon.ps1                      # uses the default path below
#   .\install-hops-daemon.ps1 -HopsPath 'D:\path\to\hops.exe'
#
# Remove it later with:
#   Unregister-ScheduledTask -TaskName 'hops-daemon' -Confirm:$false
#
# Configure hops over SSH / a remote shell after it's running: `hops tui`
# (needs a --features tui build), `hops cli ...`, or edit
# %LOCALAPPDATA%\lan-mouse\config.toml. See ..\README.md.

param(
    [string]$HopsPath = "$env:LOCALAPPDATA\hops\hops.exe"
)

if (-not (Test-Path $HopsPath)) {
    Write-Error "hops.exe not found at '$HopsPath'. Pass -HopsPath <full path>."
    exit 1
}

$action    = New-ScheduledTaskAction    -Execute $HopsPath -Argument 'daemon'
$trigger   = New-ScheduledTaskTrigger   -AtLogOn
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
# Interactive logon type = runs in the user's desktop session (can inject input);
# Highest run level = can inject into elevated windows.
$principal = New-ScheduledTaskPrincipal  -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName 'hops-daemon' -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force

Write-Host "Registered scheduled task 'hops-daemon' → $HopsPath daemon (runs at logon)."
