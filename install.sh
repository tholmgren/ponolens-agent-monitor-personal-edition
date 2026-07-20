#!/bin/sh
set -eu

PRODUCT_NAME="PonoLens"
REPOSITORY_URL="${PONOLENS_REPOSITORY_URL:-https://github.com/tholmgren/ponolens-agent-monitor-personal-edition.git}"
INSTALL_ROOT="${PONOLENS_INSTALL_DIR:-$HOME/.ponolens/application}"
DATA_ROOT="${PONOLENS_DATA_DIR:-$HOME/.ponolens}"
LOG_FILE="$DATA_ROOT/ponolens.log"
PID_FILE="$DATA_ROOT/ponolens.pid"
PORT="${PORT:-4317}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || pwd)
LAUNCHER_ROOT="$HOME/Applications/PonoLens.app"

fail() { printf '%s\n' "$PRODUCT_NAME installer: $*" >&2; exit 1; }

OS_NAME=$(uname -s 2>/dev/null || printf 'unknown')
[ "$OS_NAME" = "Darwin" ] || fail "this beta currently supports macOS only; Windows and Linux are on the roadmap"
command -v node >/dev/null 2>&1 || fail "Node.js 22.5 or newer is required: https://nodejs.org/"
NODE_BIN=$(command -v node)
NODE_MAJOR=$(node -p "Number(process.versions.node.split('.')[0])")
NODE_MINOR=$(node -p "Number(process.versions.node.split('.')[1])")
[ "$NODE_MAJOR" -gt 22 ] || { [ "$NODE_MAJOR" -eq 22 ] && [ "$NODE_MINOR" -ge 5 ]; } || fail "Node.js 22.5 or newer is required; found $(node --version)"
command -v git >/dev/null 2>&1 || fail "Git is required to download the competition preview"

mkdir -p "$DATA_ROOT"
chmod 700 "$DATA_ROOT"

if [ -f "$SCRIPT_DIR/package.json" ] && [ -d "$SCRIPT_DIR/src" ] && [ -d "$SCRIPT_DIR/public" ]; then
  SOURCE_DIR="$SCRIPT_DIR"
  printf 'Installing %s from the current checkout…\n' "$PRODUCT_NAME"
  if [ "$SOURCE_DIR" != "$INSTALL_ROOT" ]; then
    STAGE_DIR="$DATA_ROOT/application.new"
    rm -rf "$STAGE_DIR"
    mkdir -p "$STAGE_DIR"
    (cd "$SOURCE_DIR" && tar --exclude='./.git' --exclude='./.ponolens' --exclude='./.claude' --exclude='./.codex' --exclude='./.agents' --exclude='./.env' --exclude='./.env.*' --exclude='./security_best_practices_report.md' --exclude='./dist' --exclude='./build' -cf - .) | tar -xf - -C "$STAGE_DIR" || fail "could not copy the current checkout"
    rm -rf "$INSTALL_ROOT.old"
    [ ! -d "$INSTALL_ROOT" ] || mv "$INSTALL_ROOT" "$INSTALL_ROOT.old"
    mv "$STAGE_DIR" "$INSTALL_ROOT"
    rm -rf "$INSTALL_ROOT.old"
  fi
else
  printf 'Downloading %s competition preview…\n' "$PRODUCT_NAME"
  STAGE_DIR="$DATA_ROOT/application.new"
  rm -rf "$STAGE_DIR"
  git clone --depth 1 "$REPOSITORY_URL" "$STAGE_DIR" || fail "download failed; confirm you can access the repository or set PONOLENS_REPOSITORY_URL"
  rm -rf "$INSTALL_ROOT.old"
  [ ! -d "$INSTALL_ROOT" ] || mv "$INSTALL_ROOT" "$INSTALL_ROOT.old"
  mv "$STAGE_DIR" "$INSTALL_ROOT"
  rm -rf "$INSTALL_ROOT.old"
fi

if [ -f "$PID_FILE" ]; then
  OLD_PID=$(cat "$PID_FILE" 2>/dev/null || true)
  [ -z "$OLD_PID" ] || kill "$OLD_PID" 2>/dev/null || true
fi

cd "$INSTALL_ROOT"
PONOLENS_DATA_DIR="$DATA_ROOT" nohup node --experimental-sqlite src/server.mjs >>"$LOG_FILE" 2>&1 &
PONOLENS_PID=$!
printf '%s\n' "$PONOLENS_PID" > "$PID_FILE"
chmod 600 "$PID_FILE" "$LOG_FILE"

mkdir -p "$LAUNCHER_ROOT/Contents/MacOS" "$LAUNCHER_ROOT/Contents/Resources"
printf '%s\n' \
  '<?xml version="1.0" encoding="UTF-8"?>' \
  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
  '<plist version="1.0">' \
  '<dict>' \
  '  <key>CFBundleDevelopmentRegion</key><string>en</string>' \
  '  <key>CFBundleDisplayName</key><string>PonoLens</string>' \
  '  <key>CFBundleExecutable</key><string>PonoLens</string>' \
  '  <key>CFBundleIdentifier</key><string>com.ponolens.personal</string>' \
  '  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>' \
  '  <key>CFBundleName</key><string>PonoLens</string>' \
  '  <key>CFBundlePackageType</key><string>APPL</string>' \
  '  <key>CFBundleShortVersionString</key><string>0.1.0</string>' \
  '</dict>' \
  '</plist>' > "$LAUNCHER_ROOT/Contents/Info.plist"

{
  printf '%s\n' '#!/bin/sh' 'set -eu'
  printf 'NODE_BIN="%s"\n' "$NODE_BIN"
  printf '%s\n' \
    'INSTALL_ROOT="${PONOLENS_INSTALL_DIR:-$HOME/.ponolens/application}"' \
    'DATA_ROOT="${PONOLENS_DATA_DIR:-$HOME/.ponolens}"' \
    'LOG_FILE="$DATA_ROOT/ponolens.log"' \
    'PID_FILE="$DATA_ROOT/ponolens.pid"' \
    'PORT="${PORT:-4317}"' \
    'DASHBOARD_URL="http://127.0.0.1:$PORT"' \
    'if ! /usr/bin/curl -fsS -H "X-PonoLens-Request: PonoLens-Local" "$DASHBOARD_URL/api/state" >/dev/null 2>&1; then' \
    '  mkdir -p "$DATA_ROOT"' \
    '  chmod 700 "$DATA_ROOT"' \
    '  cd "$INSTALL_ROOT"' \
    '  PONOLENS_DATA_DIR="$DATA_ROOT" nohup "$NODE_BIN" --experimental-sqlite src/server.mjs >>"$LOG_FILE" 2>&1 &' \
    '  printf "%s\\n" "$!" > "$PID_FILE"' \
    '  chmod 600 "$PID_FILE" "$LOG_FILE"' \
    'fi' \
    '/usr/bin/open "$DASHBOARD_URL"'
} > "$LAUNCHER_ROOT/Contents/MacOS/PonoLens"
printf '%s\n' 'Created by the PonoLens installer.' > "$LAUNCHER_ROOT/Contents/Resources/ponolens-installer-receipt"
chmod 755 "$LAUNCHER_ROOT/Contents/MacOS/PonoLens"

printf '\nInstalled %s competition preview in %s\n' "$PRODUCT_NAME" "$INSTALL_ROOT"
printf 'Local data: %s\n' "$DATA_ROOT"
printf 'Dashboard: http://127.0.0.1:%s\n' "$PORT"
printf 'Launcher: %s\n' "$LAUNCHER_ROOT"
printf 'Redact and Block are experimental; Report Only is the stable default.\n'
printf 'Open PonoLens from your user Applications folder to restart the service and dashboard later.\n'

if [ "${PONOLENS_NO_OPEN:-0}" != "1" ]; then
  if command -v open >/dev/null 2>&1; then open "http://127.0.0.1:$PORT"; fi
fi
