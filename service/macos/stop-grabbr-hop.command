#!/bin/bash
# grabbr-hop — STOP. Boots out both launchd agents (headless daemon + menu-bar
# tray). Mirrors the Windows stop-grabbr-hop.cmd.
UID_NUM="$(id -u)"
launchctl bootout "gui/$UID_NUM/com.grabbr.hops"     2>/dev/null && echo "stopped: daemon"     || echo "daemon not running"
launchctl bootout "gui/$UID_NUM/com.grabbr.hops.gui" 2>/dev/null && echo "stopped: tray"       || echo "tray not running"
