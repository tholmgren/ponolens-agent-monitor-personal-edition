#!/bin/sh
set -eu

INSTALL_ROOT="${PONOLENS_INSTALL_DIR:-$HOME/.ponolens/application}"
DATA_ROOT="${PONOLENS_DATA_DIR:-$HOME/.ponolens}"
PID_FILE="$DATA_ROOT/ponolens.pid"
LAUNCHER_ROOT="$HOME/Applications/PonoLens.app"
AUTO_START_LABEL="com.ponolens.personal.autostart"
AUTO_START_PATH="$HOME/Library/LaunchAgents/$AUTO_START_LABEL.plist"

/bin/launchctl bootout "gui/$(id -u)/$AUTO_START_LABEL" 2>/dev/null || true
rm -f "$AUTO_START_PATH"

if [ -f "$PID_FILE" ]; then
  PID=$(cat "$PID_FILE" 2>/dev/null || true)
  [ -z "$PID" ] || kill "$PID" 2>/dev/null || true
  rm -f "$PID_FILE"
fi

rm -rf "$INSTALL_ROOT"
if [ -f "$LAUNCHER_ROOT/Contents/Resources/ponolens-installer-receipt" ]; then
  rm -rf "$LAUNCHER_ROOT"
fi
printf 'Removed the PonoLens competition preview from %s\n' "$INSTALL_ROOT"
printf 'Removed the PonoLens launcher from %s\n' "$LAUNCHER_ROOT"
printf 'Removed the PonoLens start-at-login setting.\n'
printf 'Local data remains at %s. Use Delete all local data in PonoLens before uninstalling if you want it removed.\n' "$DATA_ROOT"
