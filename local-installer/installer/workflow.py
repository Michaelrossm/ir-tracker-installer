from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import BackupManifest, CompatibilityResult, DeviceInfo, Stage
from .firmware import (
    FirmwareError,
    FirmwareSelection,
    download_latest_github,
    store_firmware,
)
from .profiles import ProfileStore, inspect_backup, parse_partition_table, sha256_file
from .transport import EspTransport, TransportError
from .tracker_client import (
    TrackerClientError,
    fetch_tracker_status,
    install_tracker_firmware,
    scan_tracker_gpio,
    scan_tracker_tx,
    test_tracker_output,
    validate_tracker_ip,
)


class WorkflowError(RuntimeError):
    pass


class InstallerWorkflow:
    def __init__(
        self,
        workspace: Path,
        transport: EspTransport,
        profile_store: ProfileStore,
        backup_root: Path | None = None,
        firmware_cache: Path | None = None,
        persistent_backup_root: Path | None = None,
    ):
        self.workspace = workspace.resolve()
        self.transport = transport
        self.profile_store = profile_store
        self.backup_root = (backup_root or workspace / "device-backups" / "installer").resolve()
        self.persistent_backup_root = (
            persistent_backup_root or self.backup_root
        ).resolve()
        self.stage = Stage.IDLE
        self.device: DeviceInfo | None = None
        self.compatibility: CompatibilityResult | None = None
        self.manifest: BackupManifest | None = None
        self.profile_id: str | None = None
        self.firmware_selection: FirmwareSelection | None = None
        self.firmware_cache = (
            firmware_cache or self.backup_root / ".firmware-cache"
        ).resolve()
        self.public_key = (self.workspace / "signing" / "firmware-signing-public.pem").resolve()
        self.gpio: dict[str, int] = {}
        self.logs: list[str] = []
        self.tracker_ip: str | None = None
        self.tracker_password = ""
        self.tracker_snapshot: dict[str, Any] | None = None
        self.pending_output_test: dict[str, Any] | None = None
        self.lock = threading.RLock()
        self.log_lock = threading.RLock()
        self.operation_lock = threading.RLock()
        self.operation: dict[str, Any] = {
            "name": "", "running": False, "phase": "Bereit", "percent": 0.0,
            "started_at": 0.0, "elapsed_s": 0.0, "error": "", "details": {},
        }

    def log(self, message: str) -> None:
        clean = message.replace("\r", "").strip()
        if clean:
            with self.log_lock:
                self.logs.append(clean[-1000:])
                del self.logs[:-300]

    def _operation_status(self) -> dict[str, Any]:
        with self.operation_lock:
            result = dict(self.operation)
            if result["running"]:
                result["elapsed_s"] = max(
                    0.0, time.monotonic() - float(result["started_at"])
                )
            result.pop("started_at", None)
            return result

    def _set_operation(
        self, *, name: str | None = None, running: bool | None = None,
        phase: str | None = None, percent: float | None = None,
        error: str | None = None, details: dict[str, Any] | None = None,
    ) -> None:
        with self.operation_lock:
            if name is not None:
                self.operation["name"] = name
            if running is not None:
                self.operation["running"] = running
                if running:
                    self.operation["started_at"] = time.monotonic()
                    self.operation["elapsed_s"] = 0.0
                else:
                    self.operation["elapsed_s"] = max(
                        0.0, time.monotonic() - float(self.operation["started_at"])
                    )
            if phase is not None:
                self.operation["phase"] = phase
            if percent is not None:
                self.operation["percent"] = max(0.0, min(100.0, percent))
            if error is not None:
                self.operation["error"] = error
            if details is not None:
                self.operation["details"] = dict(details)

    def _backup_log(self, message: str) -> None:
        self.log(message)
        matches = re.findall(r"(\d+(?:[.,]\d+)?)\s*%", message)
        if not matches:
            return
        raw = float(matches[-1].replace(",", "."))
        with self.operation_lock:
            phase = self.operation["phase"]
        if phase == "Flash vollständig lesen":
            self._set_operation(percent=2.0 + raw * 0.68)
        elif phase == "Backup bytegenau verifizieren":
            self._set_operation(percent=70.0 + raw * 0.26)

    def status(self) -> dict[str, Any]:
        with self.log_lock:
            logs = self.logs[-100:]
        return {
            "stage": self.stage.value,
            "runtime": self.transport.runtime_status(),
            "device": None if not self.device else {
                "port": self.device.port,
                "chip": self.device.chip,
                "mac": self.device.mac,
                "flash_size": self.device.flash_size,
                "virtual": self.device.virtual,
                "security": {
                    "secure_boot": self.device.security.secure_boot,
                    "flash_encryption": self.device.security.flash_encryption,
                    "secure_download_mode": self.device.security.secure_download_mode,
                },
            },
            "compatibility": None if not self.compatibility else {
                "compatible": self.compatibility.compatible,
                "profile_id": self.compatibility.profile_id,
                "confidence": self.compatibility.confidence,
                "reasons": self.compatibility.reasons,
            },
            "backup": None if not self.manifest else self.manifest.to_dict(),
            "firmware_selection": self._firmware_status(),
            "gpio": self.gpio,
            "tracker": self._tracker_status(),
            "operation": self._operation_status(),
            "output_test": self.pending_output_test,
            "logs": logs,
        }

    def _tracker_status(self) -> dict[str, Any] | None:
        if not self.tracker_ip:
            return None
        return {
            "ip": self.tracker_ip,
            "online": self.tracker_snapshot is not None,
            "data": self.tracker_snapshot,
        }

    def connect_tracker(self, ip: str, admin_password: str = "") -> dict[str, Any]:
        try:
            safe_ip = validate_tracker_ip(ip)
            simulator = getattr(self.transport, "simulated_tracker_status", None)
            runtime = self.transport.runtime_status()
            if simulator:
                if runtime.get("firmware") != "custom":
                    raise TrackerClientError(
                        "Virtuelle Custom-Firmware muss vor dem WLAN-Test installiert werden"
                    )
                if safe_ip != runtime.get("simulated_ip"):
                    raise TrackerClientError(
                        f"Virtueller Tracker ist unter {runtime.get('simulated_ip')} erreichbar"
                    )
                snapshot = simulator()
            else:
                snapshot = fetch_tracker_status(safe_ip, admin_password)
        except TrackerClientError as error:
            raise WorkflowError(str(error)) from error
        self.tracker_ip = safe_ip
        self.tracker_password = admin_password
        self.tracker_snapshot = snapshot
        self.log(f"Tracker über WLAN verbunden: {safe_ip}")
        return self.status()

    def refresh_tracker(self) -> dict[str, Any]:
        if not self.tracker_ip:
            raise WorkflowError("Zuerst die IP-Adresse des Trackers eingeben")
        try:
            simulator = getattr(self.transport, "simulated_tracker_status", None)
            self.tracker_snapshot = (
                simulator()
                if simulator
                else fetch_tracker_status(self.tracker_ip, self.tracker_password)
            )
        except TrackerClientError as error:
            self.tracker_snapshot = None
            raise WorkflowError(str(error)) from error
        return self.status()

    def disconnect_tracker(self) -> dict[str, Any]:
        self.tracker_ip = None
        self.tracker_password = ""
        self.tracker_snapshot = None
        self.log("WLAN-Prüfung beendet")
        return self.status()

    def wifi_update(self, filename: str, payload: bytes) -> dict[str, Any]:
        """Update only the signed Custom app slot; never touch the partition table."""
        if not self.tracker_ip or self.tracker_snapshot is None:
            raise WorkflowError("Zuerst den laufenden Tracker über seine WLAN-IP verbinden")
        if not self.tracker_password:
            raise WorkflowError("Für das WLAN-Update ist das Admin-Passwort erforderlich")
        if getattr(self.transport, "simulated_tracker_status", None):
            raise WorkflowError("Das echte WLAN-Update ist in der Simulation gesperrt")
        self._set_operation(
            name="wifi_update", running=True,
            phase="Signiertes Custom-App-Paket lokal prüfen", percent=5.0,
            error="", details={"filename": Path(filename).name},
        )
        try:
            selection = store_firmware(
                self.firmware_cache, filename, payload, 0x150000, "ESP32-C3",
                self.public_key, source="wifi-local-signed",
            )
            if not selection.signed or not selection.trusted:
                raise WorkflowError("WLAN-Update erfordert ein gültig signiertes .irfw-Paket")
            self.log(
                "WLAN-Update: Signatur und ESP32-C3-App geprüft; Bootloader, "
                "Partitionstabelle, Einstellungen und Historie bleiben unangetastet"
            )

            def update_progress(phase: str, percent: float) -> None:
                self._set_operation(phase=phase, percent=percent)

            install_tracker_firmware(
                self.tracker_ip, self.tracker_password, Path(filename).name,
                payload, update_progress,
            )
            self.tracker_snapshot = None
            self._set_operation(phase="Neustart und neue Custom-App prüfen", percent=78.0)
            deadline = time.monotonic() + 75.0
            last_error = ""
            while time.monotonic() < deadline:
                time.sleep(1.0)
                try:
                    snapshot = fetch_tracker_status(
                        self.tracker_ip, self.tracker_password, timeout=3.0
                    )
                    if (
                        snapshot.get("installer_wifi_ota") is True
                        and snapshot.get("installer_gpio_tx_scan") is True
                    ):
                        self.tracker_snapshot = snapshot
                        self._set_operation(
                            running=False, phase="WLAN-Update erfolgreich geprüft",
                            percent=100.0, details={
                                "filename": Path(filename).name,
                                "sha256": selection.sha256,
                                "firmware": snapshot.get("firmware", ""),
                                "app_only": True,
                            },
                        )
                        self.log(
                            f"WLAN-Update erfolgreich: {snapshot.get('firmware', 'Custom-Firmware')} antwortet wieder"
                        )
                        return self.status()
                    last_error = "Neue Installer-TX-Scan-Kennung fehlt"
                except TrackerClientError as error:
                    last_error = str(error)
            raise WorkflowError(
                "Tracker kam nach dem WLAN-Update nicht mit der erwarteten neuen Custom-App zurück"
                + (f": {last_error}" if last_error else "")
            )
        except (FirmwareError, TrackerClientError, WorkflowError) as error:
            self._set_operation(
                running=False, phase="WLAN-Update fehlgeschlagen", error=str(error)
            )
            raise WorkflowError(str(error)) from error

    def _firmware_status(self) -> dict[str, Any] | None:
        if self.firmware_selection:
            return self.firmware_selection.public()
        if not self.profile_id:
            return None
        profile = self.profile_store.get(self.profile_id)
        path = (self.workspace / profile.firmware).resolve()
        return {
            "name": path.name,
            "source": "bundled-sha256",
            "version": "integriert",
            "size": path.stat().st_size if path.is_file() else 0,
            "sha256": profile.firmware_sha256,
            "signed": False,
            "trusted": True,
        }

    def set_virtual_usb(self, connected: bool) -> dict[str, Any]:
        setter = getattr(self.transport, "set_connected", None)
        if not setter:
            raise WorkflowError("USB-Simulation ist nur im virtuellen Modus verfügbar")
        setter(connected, self.log)
        return self.status()

    def configure_virtual_gpio(
        self, rx: int, tx: int, led: int, baud: int
    ) -> dict[str, Any]:
        setter = getattr(self.transport, "set_simulation_gpio", None)
        if not setter:
            raise WorkflowError("GPIO-Vorgaben sind nur in der Simulation verfügbar")
        setter(rx, tx, led, baud, self.log)
        self.gpio = {}
        self.tracker_ip = None
        self.tracker_password = ""
        self.tracker_snapshot = None
        if self.stage in {Stage.GPIO, Stage.COMPLETE}:
            self.stage = Stage.FLASHED
        return self.status()

    def select(self, port: str) -> dict[str, Any]:
        self.device = DeviceInfo(port=port, chip="", mac="", flash_size=0)
        self.stage = Stage.SELECTED
        self.compatibility = None
        self.manifest = None
        self.firmware_selection = None
        self.gpio = {}
        self.log(f"Gerät ausgewählt: {port}")
        return self.status()

    def inspect(self) -> dict[str, Any]:
        if self.stage != Stage.SELECTED or not self.device:
            raise WorkflowError("Zuerst ein Gerät auswählen")
        self.device = self.transport.inspect(self.device.port, self.log)
        if self.device.security.blocks_custom_firmware:
            self.log("Sicherheitssperre erkannt; Flashen bleibt gesperrt")
        self.stage = Stage.INSPECTED
        return self.status()

    def backup(self) -> dict[str, Any]:
        if self.stage != Stage.INSPECTED or not self.device:
            raise WorkflowError("Hardware muss vor dem Backup vollständig geprüft werden")
        now = datetime.now(timezone.utc)
        safe_mac = self.device.mac.replace(":", "-")
        target_dir = self.backup_root / f"{now:%Y%m%dT%H%M%S%fZ}_{safe_mac}"
        target_dir.mkdir(parents=True, exist_ok=False)
        backup = target_dir / "original-full.bin"
        self._set_operation(
            name="backup", running=True, phase="Flash vollständig lesen",
            percent=1.0, error="",
        )
        try:
            self.transport.read_flash(self.device, backup, self._backup_log)
            if backup.stat().st_size != self.device.flash_size:
                raise WorkflowError(
                    f"Backupgröße {backup.stat().st_size} passt nicht zu {self.device.flash_size}"
                )
            self._set_operation(phase="Backup bytegenau verifizieren", percent=70.0)
            self.transport.verify_backup(self.device, backup, self._backup_log)
            self._set_operation(phase="Prüfsummen und Manifest erstellen", percent=97.0)
            fingerprints = inspect_backup(backup)
            self.manifest = BackupManifest(
                schema=1,
                created_utc=now.isoformat(),
                device=self.device,
                backup_file=backup.relative_to(self.backup_root).as_posix(),
                size=backup.stat().st_size,
                sha256=sha256_file(backup),
                verification="byte-for-byte",
                fingerprints=fingerprints,
            )
            (target_dir / "manifest.json").write_text(
                json.dumps(self.manifest.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as error:
            self._set_operation(
                running=False, phase="Sicherung fehlgeschlagen", error=str(error)
            )
            if backup.exists():
                backup.unlink()
            if target_dir.exists() and not any(target_dir.iterdir()):
                target_dir.rmdir()
            raise
        self.stage = Stage.BACKED_UP
        self.compatibility = self.profile_store.match(self.device, fingerprints)
        if self.device.security.blocks_custom_firmware:
            self.compatibility = CompatibilityResult(
                False,
                None,
                "blocked-by-security",
                ["Secure Boot, Flash-Verschlüsselung oder Secure Download Mode aktiv"],
            )
        if self.compatibility.compatible:
            self.profile_id = self.compatibility.profile_id
            self.stage = Stage.COMPATIBLE
            self.log(f"Kompatibles Profil erkannt: {self.profile_id}")
        else:
            self.log("Kein freigegebenes Hardwareprofil; Flashen gesperrt")
        self._set_operation(
            running=False, phase="Sicherung erfolgreich abgeschlossen", percent=100.0
        )
        return self.status()

    def _backup_path(self) -> Path:
        if not self.manifest:
            raise WorkflowError("Kein verifiziertes Backup vorhanden")
        portable = self.manifest.backup_file.replace("\\", "/")
        candidate = (self.backup_root / Path(portable)).resolve()
        if not candidate.is_relative_to(self.backup_root):
            raise WorkflowError("Ungültiger Backuppfad")
        return candidate

    def list_backups(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        if not self.backup_root.is_dir():
            return entries
        for manifest_path in sorted(
            self.backup_root.glob("*/manifest.json"), reverse=True
        ):
            try:
                manifest = BackupManifest.from_dict(
                    json.loads(manifest_path.read_text(encoding="utf-8"))
                )
                portable = manifest.backup_file.replace("\\", "/")
                backup = (self.backup_root / Path(portable)).resolve()
                valid_path = backup.is_relative_to(self.backup_root)
                available = (
                    valid_path
                    and backup.is_file()
                    and backup.stat().st_size == manifest.size
                )
                entries.append(
                    {
                        "id": manifest_path.parent.name,
                        "created_utc": manifest.created_utc,
                        "chip": manifest.device.chip,
                        "mac": manifest.device.mac,
                        "size": manifest.size,
                        "sha256": manifest.sha256,
                        "virtual": manifest.device.virtual,
                        "available": available,
                    }
                )
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                entries.append(
                    {
                        "id": manifest_path.parent.name,
                        "available": False,
                        "error": "Manifest beschädigt oder unvollständig",
                    }
                )
        grouped: list[dict[str, Any]] = []
        known: dict[tuple[str, str, bool], dict[str, Any]] = {}
        for entry in entries:
            if not entry.get("available"):
                grouped.append(entry)
                continue
            key = (
                str(entry.get("mac", "")),
                str(entry.get("sha256", "")),
                bool(entry.get("virtual", False)),
            )
            if key in known:
                known[key]["duplicate_count"] += 1
            else:
                entry["duplicate_count"] = 1
                known[key] = entry
                grouped.append(entry)
        return grouped

    def load_backup(self, backup_id: str) -> dict[str, Any]:
        if not self.device or self.stage not in {
            Stage.INSPECTED,
            Stage.BACKED_UP,
            Stage.COMPATIBLE,
        }:
            raise WorkflowError("Zuerst das angeschlossene Gerät vollständig prüfen")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", backup_id):
            raise WorkflowError("Ungültige Backup-ID")
        manifest_path = (self.backup_root / backup_id / "manifest.json").resolve()
        if not manifest_path.is_relative_to(self.backup_root) or not manifest_path.is_file():
            raise WorkflowError("Backup-Manifest nicht gefunden")
        try:
            manifest = BackupManifest.from_dict(
                json.loads(manifest_path.read_text(encoding="utf-8"))
            )
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            raise WorkflowError("Backup-Manifest ist beschädigt") from error
        identity = (self.device.chip, self.device.mac.lower(), self.device.flash_size)
        saved_identity = (
            manifest.device.chip,
            manifest.device.mac.lower(),
            manifest.device.flash_size,
        )
        if identity != saved_identity:
            raise WorkflowError("Die Sicherung gehört nicht zum angeschlossenen Gerät")
        self.manifest = manifest
        backup = self._backup_path()
        if backup.parent != manifest_path.parent:
            raise WorkflowError("Backup-Manifest verweist auf ein fremdes Verzeichnis")
        if not backup.is_file() or backup.stat().st_size != manifest.size:
            raise WorkflowError("Backupdatei fehlt oder hat eine falsche Größe")
        if sha256_file(backup) != manifest.sha256:
            raise WorkflowError("Backup-Prüfsumme stimmt nicht")
        fingerprints = inspect_backup(backup)
        if fingerprints.get("full_sha256") != manifest.fingerprints.get("full_sha256"):
            raise WorkflowError("Backup-Fingerprints stimmen nicht mit dem Manifest überein")
        self.compatibility = self.profile_store.match(self.device, fingerprints)
        self.profile_id = self.compatibility.profile_id
        self.firmware_selection = None
        self.stage = (
            Stage.COMPATIBLE if self.compatibility.compatible else Stage.BACKED_UP
        )
        self.log(f"Vorhandenes Backup geprüft und geladen: {backup_id}")
        return self.status()

    def open_backup_folder(self) -> dict[str, Any]:
        self.backup_root.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == "nt":
                os.startfile(str(self.backup_root))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(self.backup_root)])
            else:
                subprocess.Popen(["xdg-open", str(self.backup_root)])
        except OSError as error:
            raise WorkflowError(f"Sicherungsordner konnte nicht geöffnet werden: {error}") from error
        self.log(f"Sicherungsordner geöffnet: {self.backup_root}")
        return {"opened": True, "path": str(self.backup_root)}

    def _app_partition_size(self) -> int:
        if not self.manifest:
            raise WorkflowError("Zuerst ein vollständiges Backup erstellen oder laden")
        sizes = [
            int(row["size"])
            for row in self.manifest.fingerprints.get("partitions", [])
            if row.get("label") in {"ota_0", "ota_1"} and int(row.get("size", 0)) > 0
        ]
        if not sizes and self.profile_id:
            profile = self.profile_store.get(self.profile_id)
            partition_file = (self.workspace / profile.partitions).resolve()
            if (
                partition_file.is_relative_to(self.workspace)
                and partition_file.is_file()
                and sha256_file(partition_file) == profile.partitions_sha256
            ):
                sizes = [
                    int(row["size"])
                    for row in parse_partition_table(partition_file.read_bytes(), offset=0)
                    if row.get("label") in {"ota_0", "ota_1"}
                    and int(row.get("size", 0)) > 0
                ]
        if not sizes:
            raise WorkflowError("Keine sicheren OTA-App-Partitionen im Backup gefunden")
        return min(sizes)

    def select_local_firmware(self, filename: str, payload: bytes) -> dict[str, Any]:
        if self.stage != Stage.COMPATIBLE or not self.device:
            raise WorkflowError("Firmwareauswahl ist erst nach Geräteprüfung und Backup möglich")
        try:
            self.firmware_selection = store_firmware(
                self.firmware_cache,
                filename,
                payload,
                self._app_partition_size(),
                self.device.chip,
                self.public_key,
                source="local-signed" if filename.lower().endswith(".irfw") else "local-unsigned",
            )
        except FirmwareError as error:
            raise WorkflowError(str(error)) from error
        self.log(
            f"Lokale Firmware ausgewählt: {self.firmware_selection.name}, "
            f"SHA-256 {self.firmware_selection.sha256}"
        )
        return self.status()

    def select_github_firmware(self) -> dict[str, Any]:
        if self.stage != Stage.COMPATIBLE or not self.device:
            raise WorkflowError("GitHub-Download ist erst nach Geräteprüfung und Backup möglich")
        try:
            self.firmware_selection = download_latest_github(
                self.firmware_cache,
                self._app_partition_size(),
                self.device.chip,
                self.public_key,
            )
        except FirmwareError as error:
            raise WorkflowError(str(error)) from error
        self.log(
            f"Signierte GitHub-Firmware gewählt: {self.firmware_selection.version}, "
            f"SHA-256 {self.firmware_selection.sha256}"
        )
        return self.status()

    def backup_binary(self) -> tuple[str, bytes]:
        backup = self._backup_path()
        if not backup.is_file() or sha256_file(backup) != self.manifest.sha256:
            raise WorkflowError("Backupdatei fehlt oder ist beschädigt")
        return f"esp-full-{self.manifest.device.mac.replace(':', '-')}.bin", backup.read_bytes()

    def backup_report(self) -> tuple[str, bytes]:
        backup = self._backup_path()
        if not backup.is_file() or sha256_file(backup) != self.manifest.sha256:
            raise WorkflowError("Backupdatei fehlt oder ist beschädigt")
        report = json.dumps(
            self.manifest.to_dict(), indent=2, ensure_ascii=False
        ).encode("utf-8")
        return f"esp-backup-report-{self.manifest.device.mac.replace(':', '-')}.json", report

    def flash(self, confirmation: str) -> dict[str, Any]:
        if self.stage != Stage.COMPATIBLE or not self.device or not self.profile_id:
            raise WorkflowError("Flashen ist erst nach Backup und eindeutiger Kompatibilitätsprüfung erlaubt")
        expected_confirmation = (
            "UNSIGNIERTE BIN"
            if self.firmware_selection
            and self.firmware_selection.source == "local-unsigned"
            else "BACKUP OK"
        )
        if confirmation != expected_confirmation:
            raise WorkflowError("Sicherheitsbestätigung fehlt")
        backup = self._backup_path()
        if not backup.is_file() or sha256_file(backup) != self.manifest.sha256:
            raise WorkflowError("Das verifizierte Originalbackup fehlt oder wurde verändert")
        current = self.transport.inspect(self.device.port, self.log)
        identity_before = (self.device.chip, self.device.mac, self.device.flash_size)
        identity_now = (current.chip, current.mac, current.flash_size)
        if identity_now != identity_before:
            raise WorkflowError("Das angeschlossene Gerät wurde nach dem Backup ausgetauscht")
        if current.security.blocks_custom_firmware:
            raise WorkflowError("Der aktuelle Sicherheitsstatus sperrt das Flashen")
        self.transport.verify_backup(current, backup, self.log)
        self.log("Geräteidentität und Originalbackup unmittelbar vor dem Flashen erneut geprüft")
        profile = self.profile_store.get(self.profile_id)
        firmware = (
            self.firmware_selection.path
            if self.firmware_selection
            else (self.workspace / profile.firmware).resolve()
        )
        partitions = (self.workspace / profile.partitions).resolve()
        for path, expected in (
            (
                firmware,
                self.firmware_selection.sha256
                if self.firmware_selection
                else profile.firmware_sha256,
            ),
            (partitions, profile.partitions_sha256),
        ):
            allowed_root = self.firmware_cache if path == firmware and self.firmware_selection else self.workspace
            if not path.is_relative_to(allowed_root) or not path.is_file():
                raise WorkflowError(f"Freigegebenes Artefakt fehlt: {path.name}")
            if sha256_file(path) != expected.upper():
                raise WorkflowError(f"Prüfsumme stimmt nicht: {path.name}")
        mapping = {"firmware": firmware, "partitions": partitions}
        writes = [(int(item["offset"], 0), mapping[item["artifact"]]) for item in profile.writes]
        self.transport.flash(self.device, writes, self.log)
        self.stage = Stage.FLASHED
        return self.status()

    def scan_rx(self) -> dict[str, Any]:
        if not self.tracker_snapshot:
            raise WorkflowError("Zuerst die WLAN-Verbindung zum Tracker erfolgreich prüfen")
        self.gpio.pop("rx", None)
        self.gpio.pop("baud", None)
        self._set_operation(
            name="gpio_scan", running=True,
            phase="Echte GPIO-/Baud-Suche wird gestartet", percent=0, error="",
            details={
                "tested": 0, "total": 0, "current_pin": None,
                "current_baud": None, "found_pin": None, "found_baud": None,
            },
        )
        self.log(
            "GPIO-Suche gestartet: Der angezeigte Konfigurationswert wird nicht "
            "als Ergebnis übernommen; GPIO und Baudrate werden nacheinander real getestet."
        )
        self.log(
            "Nachweisregel: Ein Eingang gilt nur dann als gefunden, wenn nach dem "
            "Umschalten ein neues vollständiges SML-Telegramm mit gültiger CRC, "
            "lesbaren OBIS-Werten und plausiblen Messwerten empfangen wird."
        )
        last_candidate: tuple[Any, Any] | None = None

        def progress(state: dict[str, Any]) -> None:
            nonlocal last_candidate
            tested = int(state.get("tested", 0) or 0)
            total = max(1, int(state.get("total", 0) or 0))
            current_pin = state.get("current_pin")
            current_baud = state.get("current_baud")
            candidate = (current_pin, current_baud)
            if state.get("active") is True and candidate != last_candidate:
                self.log(
                    f"GPIO-Test {min(tested + 1, total)} von {total}: "
                    f"RX GPIO {current_pin} mit {current_baud} Baud"
                )
                last_candidate = candidate
            self._set_operation(
                phase=(
                    f"Prüfe GPIO {current_pin if current_pin is not None else '–'} mit "
                    f"{current_baud if current_baud is not None else '–'} Baud"
                ),
                percent=tested * 100.0 / total,
                details={
                    "tested": tested,
                    "total": total,
                    "current_pin": current_pin,
                    "current_baud": current_baud,
                    "found_pin": state.get("found_pin"),
                    "found_baud": state.get("found_baud"),
                },
            )
        try:
            if getattr(self.transport, "simulated_tracker_status", None):
                result = self.transport.scan_rx(self.log, progress)
            else:
                if not self.tracker_ip:
                    raise WorkflowError("Tracker-IP fehlt")
                result = scan_tracker_gpio(
                    self.tracker_ip, self.tracker_password, progress
                )
            details = self._operation_status().get("details", {})
            tested = int(details.get("tested", 0) or 0)
            total = int(details.get("total", 0) or 0)
            summary = (
                f"RX GPIO {result['pin']} mit {result['baud']} Baud bestätigt"
                + (f" – Erfolg nach {tested} von {total} Tests" if total else "")
            )
            self._set_operation(
                running=False,
                phase=summary,
                percent=100,
                details={
                    **details,
                    "found_pin": result["pin"],
                    "found_baud": result["baud"],
                },
            )
            self.log(
                f"IR-Eingang eindeutig gefunden: RX GPIO {result['pin']} mit "
                f"{result['baud']} Baud. Grund: Erst nach Aktivierung genau dieser "
                "Kombination kam ein neues vollständiges, CRC-gültiges SML-Telegramm "
                "mit erfolgreich gelesenen und plausiblen OBIS-Messwerten an."
            )
        except (TransportError, TrackerClientError) as error:
            self._set_operation(
                running=False, phase="GPIO-Suche fehlgeschlagen", error=str(error)
            )
            raise WorkflowError(str(error)) from error
        self.gpio.update({"rx": result["pin"], "baud": result["baud"]})
        for name in ("led", "tx"):
            if name in result:
                self.gpio[name] = result[name]
        if self.stage in {Stage.FLASHED, Stage.GPIO, Stage.COMPLETE}:
            self.stage = (
                Stage.COMPLETE
                if {"rx", "baud", "led", "tx"}.issubset(self.gpio)
                else Stage.GPIO
            )
        return self.status()

    def test_output(self, kind: str, pin: int) -> dict[str, Any]:
        if not self.tracker_snapshot:
            raise WorkflowError("Zuerst den Tracker über WLAN verbinden")
        if kind not in {"led", "tx"} or not 0 <= pin <= 21:
            raise WorkflowError("Ungültiger Ausgangstest")
        if pin == self.gpio.get("rx"):
            raise WorkflowError("Der gefundene RX-Eingang darf nicht als Ausgang geschaltet werden")
        simulator = getattr(self.transport, "simulated_tracker_status", None)
        if simulator:
            visible: bool | None = self.transport.test_output(kind, pin, self.log)
            can_confirm = visible
        else:
            if kind != "tx":
                raise WorkflowError(
                    "Die Gehäuse-LED kann bei echter Hardware nur manuell geprüft werden"
                )
            if not self.tracker_ip:
                raise WorkflowError("Tracker-IP fehlt")
            try:
                configured_tx = self.tracker_snapshot.get("tx_gpio")
                pulse = test_tracker_output(
                    self.tracker_ip,
                    self.tracker_password,
                    pin,
                    allow_configured_fallback=pin == configured_tx,
                )
            except TrackerClientError as error:
                raise WorkflowError(str(error)) from error
            visible = None
            can_confirm = True
            self.log(
                f"TX-Testimpuls auf GPIO {pin} gesendet. Jetzt mit Handykamera "
                "oder anhand einer eindeutigen Zählerreaktion prüfen. "
                + (
                    "Die ältere Firmware konnte dabei nur ihren aktuell "
                    "konfigurierten TX-Ausgang testen."
                    if pulse.get("mode") == "configured_tx_fallback"
                    else "Der Kandidaten-GPIO wurde nur temporär geschaltet."
                )
            )
        self.pending_output_test = {
            "kind": kind, "pin": pin, "can_confirm": can_confirm,
            "requires_user_confirmation": visible is None,
        }
        return {
            "visible": visible, "requires_confirmation": visible is None,
            "kind": kind, "pin": pin, "status": self.status(),
        }

    def scan_tx(self) -> dict[str, Any]:
        if not self.tracker_snapshot or "rx" not in self.gpio:
            raise WorkflowError("Zuerst den IR-Empfänger automatisch bestätigen")
        rx = int(self.gpio["rx"])
        self.gpio.pop("tx", None)
        self.pending_output_test = None
        self._set_operation(
            name="gpio_tx_scan", running=True,
            phase="Automatische optische TX-Suche läuft", percent=10.0,
            error="", details={"rx": rx, "tested": 0, "total": 10},
        )
        self.log(
            "TX-Suche gestartet: Jeder zulässige Ausgang wird kurz in beiden "
            "Polaritäten geschaltet. Bestätigt wird nur eine zweimal reproduzierte "
            "optische Korrelation am bereits CRC-bestätigten RX-Eingang."
        )
        try:
            simulator = getattr(self.transport, "simulated_tracker_status", None)
            if simulator:
                tx = int(self.tracker_snapshot.get("tx_gpio", -1))
                if tx < 0 or tx == rx:
                    raise WorkflowError("Simulation enthält keinen getrennten TX-Pin")
                result = {
                    "pin": tx, "inverted": False, "confidence": 100,
                    "tested": 1, "active_transitions": 0,
                    "idle_transitions": 120,
                }
            else:
                if not self.tracker_ip:
                    raise WorkflowError("Tracker-IP fehlt")
                result = scan_tracker_tx(
                    self.tracker_ip, self.tracker_password, rx
                )
        except (TrackerClientError, WorkflowError) as error:
            self._set_operation(
                running=False, phase="Automatische TX-Suche ohne eindeutiges Ergebnis",
                error=str(error),
            )
            raise WorkflowError(str(error)) from error
        self.gpio["tx"] = int(result["pin"])
        self._set_operation(
            running=False,
            phase=f"TX GPIO {result['pin']} optisch automatisch bestätigt",
            percent=100.0,
            details={**result, "rx": rx, "found_pin": result["pin"]},
        )
        self.log(
            f"IR-Sender eindeutig gefunden: TX GPIO {result['pin']}, "
            f"Konfidenz {result['confidence']} %. Nachweis: im aktiven Zustand "
            f"{result['active_transitions']} RX-Flanken, im inaktiven Zustand "
            f"{result['idle_transitions']} RX-Flanken; Ergebnis zweimal reproduziert."
        )
        if self.stage in {Stage.FLASHED, Stage.GPIO, Stage.COMPLETE}:
            self.stage = (
                Stage.COMPLETE
                if {"rx", "baud", "led", "tx"}.issubset(self.gpio)
                else Stage.GPIO
            )
        return self.status()

    def confirm_output(self, kind: str, pin: int) -> dict[str, Any]:
        if kind not in {"led", "tx"} or not 0 <= pin <= 21:
            raise WorkflowError("Ungültige GPIO-Bestätigung")
        pending = self.pending_output_test
        if (
            not pending or pending.get("kind") != kind or
            pending.get("pin") != pin or pending.get("can_confirm") is not True
        ):
            raise WorkflowError("Diesen GPIO zuerst testen und seine Reaktion prüfen")
        self.gpio[kind] = pin
        self.pending_output_test = None
        if {"rx", "baud", "led", "tx"}.issubset(self.gpio):
            self.stage = Stage.COMPLETE
        else:
            self.stage = Stage.GPIO
        if kind == "tx":
            self.log(
                f"IR-Sender als GPIO {pin} bestätigt: Der Testimpuls wurde zuvor "
                "gesendet und seine optische bzw. Zählerreaktion vom Benutzer bestätigt."
            )
        else:
            self.log(f"Gehäuse-LED als GPIO {pin} nach sichtbarem Test bestätigt")
        return self.status()

    def restore(self, confirmation: str) -> dict[str, Any]:
        if not self.device or not self.manifest:
            raise WorkflowError("Kein zugeordnetes Originalbackup vorhanden")
        if confirmation != "ORIGINAL WIEDERHERSTELLEN":
            raise WorkflowError("Wiederherstellungsbestätigung fehlt")
        backup = self._backup_path()
        if not backup.is_file():
            raise WorkflowError("Backupdatei nicht gefunden")
        if sha256_file(backup) != self.manifest.sha256:
            raise WorkflowError("Backup-Prüfsumme stimmt nicht")
        current = self.transport.inspect(self.device.port, self.log)
        if (current.chip, current.mac, current.flash_size) != (
            self.device.chip,
            self.device.mac,
            self.device.flash_size,
        ):
            raise WorkflowError("Das angeschlossene Gerät gehört nicht zu diesem Backup")
        self.transport.restore(self.device, backup, self.log)
        self.stage = Stage.INSPECTED
        self.log("Originalzustand wiederhergestellt")
        return self.status()
