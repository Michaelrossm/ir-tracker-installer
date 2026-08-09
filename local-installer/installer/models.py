from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Stage(str, Enum):
    IDLE = "idle"
    SELECTED = "selected"
    INSPECTED = "inspected"
    BACKED_UP = "backed_up"
    COMPATIBLE = "compatible"
    FLASHED = "flashed"
    GPIO = "gpio"
    COMPLETE = "complete"


@dataclass(slots=True)
class SecurityInfo:
    secure_boot: bool = False
    flash_encryption: bool = False
    secure_download_mode: bool = False
    raw: str = ""

    @property
    def blocks_custom_firmware(self) -> bool:
        return self.secure_boot or self.flash_encryption or self.secure_download_mode


@dataclass(slots=True)
class DeviceInfo:
    port: str
    chip: str
    mac: str
    flash_size: int
    security: SecurityInfo = field(default_factory=SecurityInfo)
    virtual: bool = False
    profile_hint: str | None = None


@dataclass(slots=True)
class CompatibilityResult:
    compatible: bool
    profile_id: str | None
    confidence: str
    reasons: list[str]


@dataclass(slots=True)
class BackupManifest:
    schema: int
    created_utc: str
    device: DeviceInfo
    backup_file: str
    size: int
    sha256: str
    verification: str
    fingerprints: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "BackupManifest":
        if int(value.get("schema", 0)) != 1:
            raise ValueError("Nicht unterstützte Backup-Manifest-Version")
        raw_device = dict(value["device"])
        raw_security = dict(raw_device.pop("security", {}))
        device = DeviceInfo(
            **raw_device,
            security=SecurityInfo(**raw_security),
        )
        return cls(
            schema=1,
            created_utc=str(value["created_utc"]),
            device=device,
            backup_file=str(value["backup_file"]),
            size=int(value["size"]),
            sha256=str(value["sha256"]).upper(),
            verification=str(value["verification"]),
            fingerprints=dict(value["fingerprints"]),
        )
