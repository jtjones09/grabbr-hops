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
        session=""
      else
        label="com.grabbr.hops.gui"; args="<string>gui</string><string>--hidden</string>"; log="gui.log"
        # The tray needs a window server. Saying so is better than starting and
        # failing: launchd loads an Aqua-only job when a real GUI session
        # appears. NEVER put this on the daemon, which must run headless.
        session="<key>LimitLoadToSessionType</key><string>Aqua</string>"
      fi
      plist="$HOME/Library/LaunchAgents/${label}.plist"
      cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array><string>${BIN}</string>${args}</array>
  <key>RunAtLoad</key><true/>
  <!-- Restart on an ABNORMAL exit only. A crash at login used to be permanent
       for the rest of the session (#4); plain KeepAlive:true would be wrong,
       since it also resurrects the app right after the user picks "Quit hops",
       which exits 0. ThrottleInterval names launchd's 10s floor explicitly so a
       crash loop cannot spin. -->
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Interactive</string>
  ${session}
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
