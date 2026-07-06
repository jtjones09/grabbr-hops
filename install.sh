#!/usr/bin/env bash
# hops installer (macOS / Linux). Builds hops and sets it to start at login.
#
#   ./install.sh
#
# Safe to re-run any time — it rebuilds and refreshes the install. This is a
# convenience wrapper; you can always just build and run `./target/release/hops`
# yourself (see the README "Quick start").
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
BIN="$REPO/target/release/hops"

echo "==> Building hops (first build takes a couple of minutes)…"
( cd "$REPO" && cargo build --release --no-default-features --features "tui slint" )

case "$(uname -s)" in
  Darwin)
    echo "==> Setting up login agents: background receiver + menu-bar tray…"
    mkdir -p "$HOME/hops/logs" "$HOME/Library/LaunchAgents"
    uid="$(id -u)"
    # Two agents, mirroring the app model: the daemon (headless) and the tray.
    for kind in daemon gui; do
      if [ "$kind" = daemon ]; then
        label="com.grabbr.hops"; args="<string>daemon</string>"; log="daemon.log"
      else
        label="com.grabbr.hops.gui"; args="<string>gui</string><string>--hidden</string>"; log="gui.log"
      fi
      plist="$HOME/Library/LaunchAgents/${label}.plist"
      cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array><string>${BIN}</string>${args}</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>${HOME}/hops/logs/${log}</string>
  <key>StandardErrorPath</key><string>${HOME}/hops/logs/${log}</string>
</dict></plist>
PLIST
      launchctl bootout "gui/${uid}/${label}" 2>/dev/null || true
      launchctl bootstrap "gui/${uid}" "$plist"
    done
    echo
    echo "✅  hops is running (look for the tray icon in your menu bar)."
    echo "⚠️  ONE manual step — macOS needs your OK for hops to move the cursor:"
    echo "      System Settings → Privacy & Security → Accessibility → turn on \"hops\""
    open "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility" 2>/dev/null || true
    ;;
  Linux)
    echo "==> Setting up the systemd user service…"
    mkdir -p "$HOME/.config/systemd/user"
    cat > "$HOME/.config/systemd/user/hops.service" <<UNIT
[Unit]
Description=hops — software KVM
After=graphical-session.target
[Service]
ExecStart=${BIN} daemon
Restart=on-failure
[Install]
WantedBy=default.target
UNIT
    systemctl --user daemon-reload
    systemctl --user enable --now hops.service
    echo
    echo "✅  hops daemon installed and running."
    echo "⚠️  Let it inject input without root — add yourself to the input group:"
    echo "      sudo usermod -aG input \"\$USER\"   # then log out and back in"
    echo "    Configure it with:  hops gui   (or  hops tui  over SSH)"
    ;;
  *)
    echo "Built at: $BIN — run it directly."
    ;;
esac
