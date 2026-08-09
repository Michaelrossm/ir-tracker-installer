# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

installer_dir = Path(SPECPATH)
project_root = installer_dir.parent

datas = [
    (str(installer_dir / "ui" / "index.html"), "local-installer/ui"),
    (str(installer_dir / "profiles"), "local-installer/profiles"),
    (str(project_root / "signing" / "firmware-signing-public.pem"), "signing"),
    (
        str(project_root / "release" / "ir-tracker-custom-1.0.2-beta.1-usb.bin"),
        "release",
    ),
    (str(project_root / "release" / "partitions-1.0.2-beta.1.bin"), "release"),
]
datas += collect_data_files("esptool")
datas += collect_data_files("espefuse")
hiddenimports = (
    collect_submodules("esptool")
    + collect_submodules("espefuse")
    + collect_submodules("bitstring")
    + collect_submodules("bitarray")
    + collect_submodules("serial")
)

a = Analysis(
    [str(installer_dir / "start.py")],
    pathex=[str(installer_dir)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="IR-Tracker-Installer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
