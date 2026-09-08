<#
  hops-ctl.ps1 - address the daemon and the tray SEPARATELY.

  Both are hops.exe, so `taskkill /f /im hops.exe` cannot tell them apart: it
  force-kills everything that matches. That is why restarting a crashed tray
  took the daemon with it, and why every launcher stopped a working KVM to do
  it. They are told apart here by their command line, and stopped by PID -
  which also means no elevated session, since stopping your own process by PID
  is not a privileged operation.

  Usage:
    hops-ctl.ps1 status
    hops-ctl.ps1 start-gui     [-Bin <path>]   # no-op if one is already up
    hops-ctl.ps1 stop-gui
    hops-ctl.ps1 restart-gui   [-Bin <path>]
    hops-ctl.ps1 start-daemon  [-Bin <path>] [-DaemonCmd <path>]
    hops-ctl.ps1 stop-daemon
#>
param(
  [Parameter(Mandatory=$true, Position=0)]
  [ValidateSet('status','start-gui','stop-gui','restart-gui','start-daemon','stop-daemon')]
  [string]$Action,
  [string]$Bin,
  [string]$DaemonCmd,
  # Print what would be stopped or started, and do nothing. The point of this
  # script is that it touches one role and not the other; -DryRun is how that
  # is checked without stopping a working KVM to find out.
  [switch]$DryRun
)

# NOTE: run this from an interactive desktop session, not over SSH. A tray
# started from a remote session lands in a different session and its icon never
# appears on the desktop.

$ErrorActionPreference = 'Stop'

function Get-HopsProcs {
  # CommandLine is what distinguishes them; Name alone cannot.
  $all = Get-CimInstance Win32_Process -Filter "Name='hops.exe'" -ErrorAction SilentlyContinue
  if (-not $all) { return @() }
  $all | ForEach-Object {
    $cl = [string]$_.CommandLine
    $role = if ($cl -match '\sgui(\s|$)') { 'gui' }
            elseif ($cl -match '\sdaemon(\s|$)') { 'daemon' }
            else { 'other' }
    [pscustomobject]@{ Pid = $_.ProcessId; Role = $role; CommandLine = $cl; Path = $_.ExecutablePath }
  }
}

function Stop-Role([string]$role) {
  $hit = @(Get-HopsProcs | Where-Object Role -eq $role)
  if ($hit.Count -eq 0) { Write-Output "no $role running"; return }
  foreach ($p in $hit) {
    if ($DryRun) { Write-Output "would stop $role (pid $($p.Pid))"; continue }
    # By PID, never by image name: /im would take the other role with it.
    Stop-Process -Id $p.Pid -Force -ErrorAction SilentlyContinue
    Write-Output "stopped $role (pid $($p.Pid))"
  }
}

switch ($Action) {
  'status' {
    $procs = @(Get-HopsProcs)
    if ($procs.Count -eq 0) { Write-Output 'nothing running'; break }
    foreach ($p in $procs) { Write-Output "$($p.Role)  pid=$($p.Pid)  $($p.Path)" }
  }
  'stop-gui'    { Stop-Role 'gui' }
  'stop-daemon' { Stop-Role 'daemon' }
  'start-gui' {
    if (@(Get-HopsProcs | Where-Object Role -eq 'gui').Count -gt 0) {
      Write-Output 'tray already running - leaving it alone'; break
    }
    if (-not $Bin) { throw 'start-gui needs -Bin <path to hops.exe>' }
    if (-not (Test-Path $Bin)) { throw "no binary at $Bin" }
    # Detached, with its own hidden console. Started as a child of a console
    # that then exits, the tray dies with that console - silently, because
    # nothing panicked.
    Start-Process -FilePath $Bin -ArgumentList 'gui','--hidden' -WindowStyle Hidden | Out-Null
    Write-Output "started tray from $Bin"
  }
  'restart-gui' {
    Stop-Role 'gui'
    Start-Sleep -Milliseconds 400
    if (-not $Bin) { throw 'restart-gui needs -Bin <path to hops.exe>' }
    Start-Process -FilePath $Bin -ArgumentList 'gui','--hidden' -WindowStyle Hidden | Out-Null
    Write-Output "restarted tray from $Bin"
  }
  'start-daemon' {
    if (@(Get-HopsProcs | Where-Object Role -eq 'daemon').Count -gt 0) {
      Write-Output 'daemon already running - leaving it alone'; break
    }
    if (-not $DaemonCmd) { throw 'start-daemon needs -DaemonCmd <path to the daemon .cmd>' }
    if (-not (Test-Path $DaemonCmd)) { throw "no launcher at $DaemonCmd" }
    Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "`"$DaemonCmd`"" -WindowStyle Hidden | Out-Null
    Write-Output "started daemon via $DaemonCmd"
  }
}
