from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


IRFW_MAGIC = b"IRFW100\0"
GITHUB_API = "https://api.github.com/repos/Michaelrossm/ir-tracker-offline/releases?per_page=20"
GITHUB_ASSET_PREFIX = "https://github.com/Michaelrossm/ir-tracker-offline/releases/download/"
MAX_PACKAGE_BYTES = 4 * 1024 * 1024


class FirmwareError(RuntimeError):
    pass


@dataclass(slots=True)
class FirmwareSelection:
    name: str
    source: str
    version: str
    size: int
    sha256: str
    signed: bool
    trusted: bool
    path: Path

    def public(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("path")
        return value


def _validate_esp_app(firmware: bytes, max_size: int, expected_chip: str) -> None:
    if len(firmware) < 1024 or len(firmware) > max_size:
        raise FirmwareError(
            f"Firmwaregröße {len(firmware)} Byte liegt außerhalb des erlaubten App-Bereichs"
        )
    if firmware[0] != 0xE9 or not 1 <= firmware[1] <= 16:
        raise FirmwareError("Die Datei ist kein gültiges ESP-Anwendungsabbild")
    expected_ids = {"ESP32-C3": 5}
    expected_id = next(
        (chip_id for name, chip_id in expected_ids.items() if expected_chip.upper().startswith(name)),
        None,
    )
    image_chip = int.from_bytes(firmware[12:14], "little")
    if expected_id is not None and image_chip != expected_id:
        raise FirmwareError(
            f"Firmware ist für ESP-Chip-ID {image_chip}, erwartet wird {expected_id}"
        )


def unwrap_signed_package(package: bytes, public_key_path: Path) -> bytes:
    if len(package) < 16:
        raise FirmwareError("Signiertes Firmwarepaket ist zu kurz")
    magic, firmware_size, signature_size, reserved = struct.unpack("<8sIHH", package[:16])
    expected = 16 + signature_size + firmware_size
    if (
        magic != IRFW_MAGIC
        or reserved != 0
        or not 64 <= signature_size <= 80
        or expected != len(package)
    ):
        raise FirmwareError("Ungültiger IRFW-Paketkopf")
    signature = package[16 : 16 + signature_size]
    firmware = package[16 + signature_size :]
    digest = hashlib.sha256(firmware).digest()
    try:
        key = serialization.load_pem_public_key(public_key_path.read_bytes())
        key.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    except (OSError, ValueError, InvalidSignature) as error:
        raise FirmwareError("Firmware-Signatur ist ungültig") from error
    return firmware


def store_firmware(
    cache: Path,
    filename: str,
    payload: bytes,
    max_size: int,
    expected_chip: str,
    public_key_path: Path,
    source: str,
    version: str = "lokal",
) -> FirmwareSelection:
    safe_name = Path(filename).name
    signed = safe_name.lower().endswith(".irfw")
    if signed:
        firmware = unwrap_signed_package(payload, public_key_path)
    elif safe_name.lower().endswith(".bin"):
        firmware = payload
    else:
        raise FirmwareError("Nur .bin- oder signierte .irfw-Dateien werden akzeptiert")
    _validate_esp_app(firmware, max_size, expected_chip)
    digest = hashlib.sha256(firmware).hexdigest().upper()
    cache.mkdir(parents=True, exist_ok=True)
    target = (cache / f"firmware-{digest}.bin").resolve()
    if not target.is_relative_to(cache.resolve()):
        raise FirmwareError("Ungültiger Firmware-Zielpfad")
    temporary = target.with_suffix(".tmp")
    temporary.write_bytes(firmware)
    temporary.replace(target)
    return FirmwareSelection(
        name=safe_name,
        source=source,
        version=version,
        size=len(firmware),
        sha256=digest,
        signed=signed,
        trusted=signed,
        path=target,
    )


def download_latest_github(
    cache: Path,
    max_size: int,
    expected_chip: str,
    public_key_path: Path,
) -> FirmwareSelection:
    request = Request(
        GITHUB_API,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "IR-Tracker-Installer",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=15) as response:
            releases = json.loads(response.read(1024 * 1024).decode("utf-8"))
    except HTTPError as error:
        if error.code == 404:
            raise FirmwareError("GitHub-Repository oder Release-Liste nicht gefunden") from error
        raise FirmwareError(f"GitHub antwortet mit HTTP {error.code}") from error
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
        raise FirmwareError(f"GitHub-Firmware konnte nicht abgefragt werden: {error}") from error
    if not isinstance(releases, list):
        raise FirmwareError("GitHub hat keine gültige Release-Liste geliefert")
    release = next((item for item in releases if not item.get("draft")), None)
    if not release:
        raise FirmwareError("Noch kein veröffentlichtes GitHub-Release mit Firmware vorhanden")
    assets = release.get("assets") or []
    asset = next(
        (
            item
            for item in assets
            if str(item.get("name", "")).lower().startswith("ir-tracker-custom-")
            and str(item.get("name", "")).lower().endswith(".irfw")
        ),
        None,
    )
    if not asset:
        raise FirmwareError("Im neuesten GitHub-Release fehlt ein signiertes .irfw-Paket")
    url = str(asset.get("browser_download_url", ""))
    if not url.startswith(GITHUB_ASSET_PREFIX):
        raise FirmwareError("GitHub-Asset besitzt keine freigegebene Downloadadresse")
    declared_size = int(asset.get("size", 0))
    if declared_size <= 0 or declared_size > MAX_PACKAGE_BYTES:
        raise FirmwareError("GitHub-Firmwarepaket hat eine unzulässige Größe")
    try:
        with urlopen(Request(url, headers={"User-Agent": "IR-Tracker-Installer"}), timeout=30) as response:
            package = response.read(MAX_PACKAGE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        raise FirmwareError(f"GitHub-Firmware konnte nicht geladen werden: {error}") from error
    if len(package) != declared_size or len(package) > MAX_PACKAGE_BYTES:
        raise FirmwareError("GitHub-Downloadgröße stimmt nicht mit dem Release überein")
    return store_firmware(
        cache,
        str(asset["name"]),
        package,
        max_size,
        expected_chip,
        public_key_path,
        source="github-signed",
        version=str(release.get("tag_name") or release.get("name") or "unbekannt"),
    )
