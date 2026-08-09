from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


INSTALLER_VERSION = "1.0.1-beta.1"
GITHUB_API = "https://api.github.com/repos/Michaelrossm/ir-tracker-installer/releases?per_page=20"
GITHUB_ASSET_PREFIX = "https://github.com/Michaelrossm/ir-tracker-installer/releases/download/"
MAX_INSTALLER_BYTES = 100 * 1024 * 1024


class InstallerUpdateError(RuntimeError):
    pass


@dataclass(slots=True)
class InstallerUpdate:
    current_version: str = INSTALLER_VERSION
    available: bool = False
    version: str = ""
    name: str = ""
    url: str = ""
    size: int = 0
    sha256: str = ""
    staged_path: str = ""

    def public(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("url", None)
        return value


def _version_number(value: str) -> tuple[int, int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-beta\.(\d+))?", value)
    if not match:
        return (0, 0, 0, 0)
    major, minor, patch = (int(match.group(index)) for index in range(1, 4))
    beta = int(match.group(4)) if match.group(4) else 255
    return major, minor, patch, beta


def _asset_prefix() -> str:
    return "IR-Tracker-Installer-Windows-" if os.name == "nt" else "IR-Tracker-Installer-Linux-"


def check_installer_update() -> InstallerUpdate:
    request = Request(
        GITHUB_API,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"IR-Tracker-Installer/{INSTALLER_VERSION}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=15) as response:
            releases = json.loads(response.read(1024 * 1024).decode("utf-8"))
    except HTTPError as error:
        raise InstallerUpdateError(f"GitHub antwortet mit HTTP {error.code}") from error
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
        raise InstallerUpdateError(f"Installer-Update konnte nicht abgefragt werden: {error}") from error
    if not isinstance(releases, list):
        raise InstallerUpdateError("GitHub hat keine gueltige Release-Liste geliefert")
    current = _version_number(INSTALLER_VERSION)
    for release in releases:
        if release.get("draft"):
            continue
        version = str(release.get("tag_name") or "")
        if _version_number(version) <= current:
            continue
        for asset in release.get("assets") or []:
            name = str(asset.get("name") or "")
            url = str(asset.get("browser_download_url") or "")
            digest = str(asset.get("digest") or "")
            size = int(asset.get("size") or 0)
            if (
                not name.startswith(_asset_prefix())
                or not url.startswith(GITHUB_ASSET_PREFIX)
                or not digest.startswith("sha256:")
                or not re.fullmatch(r"[0-9a-fA-F]{64}", digest[7:])
                or size < 1024
                or size > MAX_INSTALLER_BYTES
            ):
                continue
            return InstallerUpdate(
                available=True,
                version=version.removeprefix("v"),
                name=name,
                url=url,
                size=size,
                sha256=digest[7:].upper(),
            )
    return InstallerUpdate()


def stage_installer_update(update: InstallerUpdate, target_directory: Path) -> InstallerUpdate:
    if not update.available or not update.url.startswith(GITHUB_ASSET_PREFIX):
        raise InstallerUpdateError("Kein verifiziertes Installer-Update ausgewaehlt")
    target_directory.mkdir(parents=True, exist_ok=True)
    target = (target_directory / Path(update.name).name).resolve()
    if not target.is_relative_to(target_directory.resolve()):
        raise InstallerUpdateError("Ungueltiger Update-Zielpfad")
    try:
        with urlopen(Request(update.url, headers={"User-Agent": "IR-Tracker-Installer"}), timeout=60) as response:
            payload = response.read(MAX_INSTALLER_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        raise InstallerUpdateError(f"Installer-Update konnte nicht geladen werden: {error}") from error
    if len(payload) != update.size or len(payload) > MAX_INSTALLER_BYTES:
        raise InstallerUpdateError("Downloadgroesse stimmt nicht mit dem Release ueberein")
    if hashlib.sha256(payload).hexdigest().upper() != update.sha256:
        raise InstallerUpdateError("SHA-256-Pruefsumme des Installer-Updates ist ungueltig")
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_bytes(payload)
    if os.name != "nt":
        temporary.chmod(0o755)
    temporary.replace(target)
    update.staged_path = str(target)
    return update
