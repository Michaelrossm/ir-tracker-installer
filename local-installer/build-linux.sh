#!/usr/bin/env sh
set -eu
INSTALLER_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname "$INSTALLER_DIR")
VENV_DIR="$INSTALLER_DIR/.venv-linux"
cd "$PROJECT_DIR"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/python" -m pip install --disable-pip-version-check -r "$INSTALLER_DIR/build-requirements.txt"
"$VENV_DIR/bin/python" -m PyInstaller --noconfirm --clean \
  --distpath "$INSTALLER_DIR/dist-linux" \
  --workpath "$INSTALLER_DIR/build-linux" \
  "$INSTALLER_DIR/ir-tracker-installer.spec"
chmod +x "$INSTALLER_DIR/dist-linux/IR-Tracker-Installer"
printf 'Fertig: %s\n' "$INSTALLER_DIR/dist-linux/IR-Tracker-Installer"
