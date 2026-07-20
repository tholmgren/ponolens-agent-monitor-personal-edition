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

fail() { printf '%s\n' "$PRODUCT_NAME installer: $*" >&2; exit 1; }

command -v node >/dev/null 2>&1 || fail "Node.js 22.5 or newer is required: https://nodejs.org/"
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

printf '\nInstalled %s competition preview in %s\n' "$PRODUCT_NAME" "$INSTALL_ROOT"
printf 'Local data: %s\n' "$DATA_ROOT"
printf 'Dashboard: http://127.0.0.1:%s\n' "$PORT"
printf 'Redact and Block are experimental; Report Only is the stable default.\n'
printf 'This is the script-installed competition preview, not the planned PonoLens Personal Mac application.\n'

if [ "${PONOLENS_NO_OPEN:-0}" != "1" ]; then
  if command -v open >/dev/null 2>&1; then open "http://127.0.0.1:$PORT"; fi
fi
