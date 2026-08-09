from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import CompatibilityResult, DeviceInfo


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def parse_partition_table(data: bytes, offset: int = 0x8000) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    end = min(len(data), offset + 0xC00)
    for cursor in range(offset, end, 32):
        entry = data[cursor : cursor + 32]
        if len(entry) < 32 or int.from_bytes(entry[0:2], "little") != 0x50AA:
            break
        rows.append(
            {
                "type": entry[2],
                "subtype": entry[3],
                "offset": int.from_bytes(entry[4:8], "little"),
                "size": int.from_bytes(entry[8:12], "little"),
                "label": entry[12:28].split(b"\0", 1)[0].decode("ascii", "replace"),
                "flags": int.from_bytes(entry[28:32], "little"),
            }
        )
    return rows


def inspect_backup(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 0x10000:
        raise ValueError("Backup is too small to contain an ESP partition table")
    partitions = parse_partition_table(data)
    app = next((row for row in partitions if row["label"] == "ota_0"), None)
    app_hash = None
    if app and app["offset"] + app["size"] <= len(data):
        app_hash = sha256_bytes(data[app["offset"] : app["offset"] + app["size"]])
    return {
        "full_sha256": sha256_bytes(data),
        "boot_region_sha256": sha256_bytes(data[0:0x8000]),
        "partition_table_sha256": sha256_bytes(data[0x8000:0x9000]),
        "ota_0_sha256": app_hash,
        "partitions": partitions,
    }


@dataclass(slots=True)
class DeviceProfile:
    profile_id: str
    name: str
    chips: list[str]
    flash_size: int
    partition_table_sha256: str | None
    boot_region_sha256: str | None
    ota_0_sha256: list[str]
    firmware: str
    firmware_sha256: str
    partitions: str
    partitions_sha256: str
    writes: list[dict[str, Any]]
    gpio: dict[str, int]
    virtual_only: bool = False

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DeviceProfile":
        return cls(**value)


class ProfileStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.profiles = [
            DeviceProfile.from_dict(json.loads(path.read_text(encoding="utf-8")))
            for path in sorted(directory.glob("*.json"))
        ]

    def get(self, profile_id: str) -> DeviceProfile:
        for profile in self.profiles:
            if profile.profile_id == profile_id:
                return profile
        raise KeyError(profile_id)

    def match(
        self, device: DeviceInfo, fingerprints: dict[str, Any]
    ) -> CompatibilityResult:
        failures: list[str] = []
        normalized_chip = device.chip.upper().replace("_", "-")
        for profile in self.profiles:
            if profile.virtual_only:
                if device.virtual and device.profile_hint == profile.profile_id:
                    return CompatibilityResult(
                        True,
                        profile.profile_id,
                        "virtual-test",
                        ["Virtuelles Testprofil eindeutig zugeordnet"],
                    )
                continue
            reasons: list[str] = []
            accepted_chips = {chip.upper().replace("_", "-") for chip in profile.chips}
            if not any(normalized_chip.startswith(chip) for chip in accepted_chips):
                reasons.append(f"Chip {device.chip} ist nicht freigegeben")
            if device.flash_size != profile.flash_size:
                reasons.append(
                    f"Flashgröße {device.flash_size} statt {profile.flash_size} Byte"
                )
            if profile.partition_table_sha256 and (
                fingerprints.get("partition_table_sha256")
                != profile.partition_table_sha256.upper()
            ):
                reasons.append("Unbekannte Partitionstabelle")
            if profile.boot_region_sha256 and (
                fingerprints.get("boot_region_sha256")
                != profile.boot_region_sha256.upper()
            ):
                reasons.append("Unbekannter Bootloaderbereich")
            accepted_apps = {item.upper() for item in profile.ota_0_sha256}
            if accepted_apps and fingerprints.get("ota_0_sha256") not in accepted_apps:
                reasons.append("Original-Firmwareversion ist nicht freigegeben")
            if not reasons:
                return CompatibilityResult(
                    True,
                    profile.profile_id,
                    "exact-fingerprint",
                    [
                        "Chip und Flashgröße stimmen",
                        "Bootloader, Partitionstabelle und Original-App sind bekannt",
                    ],
                )
            failures.extend(f"{profile.name}: {reason}" for reason in reasons)
        return CompatibilityResult(False, None, "none", failures or ["Kein Geräteprofil vorhanden"])
