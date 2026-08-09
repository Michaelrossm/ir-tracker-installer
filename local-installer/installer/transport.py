from __future__ import annotations

import re
import io
import subprocess
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable

from .models import DeviceInfo, SecurityInfo

LogFn = Callable[[str], None]


class TransportError(RuntimeError):
    pass


class _StreamingCapture(io.StringIO):
    """Capture CLI output while forwarding complete lines and CR progress updates."""

    def __init__(self, log: LogFn):
        super().__init__()
        self.log = log
        self.pending = ""

    def write(self, value: str) -> int:
        written = super().write(value)
        self.pending += value.replace("\r", "\n")
        while "\n" in self.pending:
            line, self.pending = self.pending.split("\n", 1)
            if line.strip():
                self.log(line)
        return written

    def finish(self) -> None:
        if self.pending.strip():
            self.log(self.pending)
        self.pending = ""


class EspTransport(ABC):
    @abstractmethod
    def list_ports(self) -> list[dict[str, str]]: ...

    @abstractmethod
    def inspect(self, port: str, log: LogFn) -> DeviceInfo: ...

    @abstractmethod
    def read_flash(self, device: DeviceInfo, destination: Path, log: LogFn) -> None: ...

    @abstractmethod
    def verify_backup(self, device: DeviceInfo, backup: Path, log: LogFn) -> None: ...

    @abstractmethod
    def flash(
        self, device: DeviceInfo, writes: list[tuple[int, Path]], log: LogFn
    ) -> None: ...

    @abstractmethod
    def restore(self, device: DeviceInfo, backup: Path, log: LogFn) -> None: ...

    def scan_rx(
        self,
        log: LogFn,
        progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, int]:
        raise TransportError("GPIO scan requires the installed firmware")

    def test_output(self, kind: str, pin: int, log: LogFn) -> bool:
        raise TransportError("GPIO output test requires the installed firmware")

    def runtime_status(self) -> dict[str, object]:
        return {
            "transport": "usb",
            "connected": True,
            "firmware": "unknown",
            "firmware_label": "Noch nicht erkannt",
        }


class RealEspTransport(EspTransport):
    def __init__(self, python: str = sys.executable):
        self.python = python

    def _run(self, arguments: list[str], log: LogFn) -> str:
        if getattr(sys, "frozen", False):
            import esptool

            capture = _StreamingCapture(log)
            code = 0
            try:
                with redirect_stdout(capture), redirect_stderr(capture):
                    esptool.main(arguments)
            except SystemExit as error:
                code = int(error.code or 0)
            except Exception as error:
                code = 1
                capture.write(f"\n{type(error).__name__}: {error}\n")
            capture.finish()
            output = capture.getvalue()
            log("esptool (eingebettet): " + " ".join(arguments))
            if code:
                details = [line.strip() for line in output.splitlines() if line.strip()]
                reason = details[-1] if details else f"Fehlercode {code}"
                raise TransportError(f"esptool: {reason}")
            return output
        command = [self.python, "-m", "esptool", *arguments]
        log("$ " + " ".join(command))
        process = subprocess.Popen(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            errors="replace",
            bufsize=1,
        )
        output_lines: list[str] = []
        if process.stdout:
            for line in process.stdout:
                clean = line.rstrip("\r\n")
                output_lines.append(clean)
                if clean:
                    log(clean)
        return_code = process.wait()
        output = "\n".join(output_lines)
        if return_code:
            details = [line.strip() for line in output.splitlines() if line.strip()]
            reason = details[-1] if details else f"Fehlercode {return_code}"
            raise TransportError(f"esptool: {reason}")
        return output

    def _read_efuse_summary(self, port: str, log: LogFn) -> str:
        arguments = ["--port", port, "summary"]
        if getattr(sys, "frozen", False):
            import espefuse

            capture = io.StringIO()
            try:
                with redirect_stdout(capture), redirect_stderr(capture):
                    espefuse.main(arguments)
            except SystemExit as error:
                if int(error.code or 0):
                    raise TransportError("eFuse-Sicherheitsstatus konnte nicht gelesen werden") from error
            except BaseException as error:
                if isinstance(error, (KeyboardInterrupt, GeneratorExit)):
                    raise
                raise TransportError(
                    "eFuse-Sicherheitsstatus konnte nicht gelesen werden: "
                    f"{type(error).__name__}: {error}"
                ) from error
            output = capture.getvalue()
        else:
            process = subprocess.run(
                [self.python, "-m", "espefuse", *arguments],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                errors="replace",
            )
            output = process.stdout or ""
            if process.returncode:
                raise TransportError("eFuse-Sicherheitsstatus konnte nicht gelesen werden")
        log("eFuse-Fallback für klassischen ESP32 (nur lesend)")
        for line in output.splitlines():
            log(line)
        return output

    def list_ports(self) -> list[dict[str, str]]:
        try:
            from serial.tools import list_ports
        except ImportError as error:
            raise TransportError("pyserial/esptool is not installed") from error
        return [
            {
                "port": item.device,
                "description": item.description or "Serial device",
                "hwid": item.hwid or "",
            }
            for item in list_ports.comports()
        ]

    def inspect(self, port: str, log: LogFn) -> DeviceInfo:
        flash = self._run(["--port", port, "flash-id"], log)
        chip_match = re.search(r"Chip type:\s*([^\r\n]+)", flash, re.I)
        mac_match = re.search(r"MAC:\s*([0-9a-f:]{17})", flash, re.I)
        size_match = re.search(r"(?:Detected flash size|Flash size):\s*(\d+)\s*(MB|KB)", flash, re.I)
        if not chip_match or not mac_match or not size_match:
            raise TransportError("Chip, MAC-Adresse oder Flashgröße konnten nicht sicher erkannt werden")
        chip = chip_match.group(1).strip()
        efuse_fallback = False
        try:
            security_raw = self._run(["--port", port, "get-security-info"], log)
        except TransportError:
            if not chip.upper().startswith("ESP32-") or chip.upper().startswith("ESP32-C"):
                raise
            security_raw = self._read_efuse_summary(port, log)
            efuse_fallback = True
        multiplier = 1024 * 1024 if size_match.group(2).upper() == "MB" else 1024
        security_lower = security_raw.lower()
        flash_crypt_match = re.search(
            r"flash_crypt_cnt[^\r\n]*=\s*(\d+)", security_lower
        )
        if efuse_fallback:
            secure_boot = bool(
                re.search(r"abs_done_[01][^\r\n]*=\s*true", security_lower)
                or re.search(r"secure_boot_en[^\r\n]*=\s*true", security_lower)
            )
            flash_encryption = bool(
                flash_crypt_match
                and bin(int(flash_crypt_match.group(1))).count("1") % 2 == 1
            )
            secure_download_mode = bool(
                re.search(r"uart_download_dis[^\r\n]*=\s*true", security_lower)
                or re.search(r"dis_download_mode[^\r\n]*=\s*true", security_lower)
            )
        else:
            secure_boot = bool(
                re.search(r"secure boot[^\r\n]*(enabled|true)", security_lower)
            )
            flash_encryption = bool(
                re.search(r"flash encryption[^\r\n]*(enabled|true)", security_lower)
            )
            secure_download_mode = bool(
                re.search(r"secure download[^\r\n]*(enabled|true)", security_lower)
            )
        security = SecurityInfo(
            secure_boot=secure_boot,
            flash_encryption=flash_encryption,
            secure_download_mode=secure_download_mode,
            raw=security_raw,
        )
        return DeviceInfo(
            port=port,
            chip=chip,
            mac=mac_match.group(1).lower(),
            flash_size=int(size_match.group(1)) * multiplier,
            security=security,
        )

    def read_flash(self, device: DeviceInfo, destination: Path, log: LogFn) -> None:
        self._run(
            ["--port", device.port, "--baud", "460800", "read-flash", "0", "ALL", str(destination)],
            log,
        )

    def verify_backup(self, device: DeviceInfo, backup: Path, log: LogFn) -> None:
        self._run(
            ["--port", device.port, "--baud", "460800", "verify-flash", "0", str(backup)],
            log,
        )

    def flash(
        self, device: DeviceInfo, writes: list[tuple[int, Path]], log: LogFn
    ) -> None:
        arguments = ["--port", device.port, "--baud", "460800", "write-flash"]
        for offset, path in writes:
            arguments.extend([hex(offset), str(path)])
        self._run(arguments, log)

    def restore(self, device: DeviceInfo, backup: Path, log: LogFn) -> None:
        self._run(
            ["--port", device.port, "--baud", "460800", "write-flash", "0", str(backup)],
            log,
        )

    def runtime_status(self) -> dict[str, object]:
        return {
            "transport": "usb",
            "connected": True,
            "firmware": "unknown",
            "firmware_label": "Wird nach dem Backup erkannt",
        }


class VirtualEspTransport(EspTransport):
    def __init__(
        self,
        flash_size: int = 4 * 1024 * 1024,
        original_image: Path | None = None,
    ):
        payload = original_image.read_bytes() if original_image and original_image.is_file() else b""
        if payload and len(payload) != flash_size:
            raise TransportError("Virtual original image has an unexpected flash size")
        self.memory = bytearray(payload or (b"\xFF" * flash_size))
        self.original = bytes(self.memory)
        self.flashed = False
        self.connected = True
        self.firmware = "solakon-original"
        self.rx_pin = 3
        self.tx_pin = 6
        self.led_pin = 5
        self.baud = 9600
        self.simulated_ip = "192.168.4.1"

    def list_ports(self) -> list[dict[str, str]]:
        if not self.connected:
            return []
        return [{"port": "VIRTUAL0", "description": "Virtueller ESP32-C3", "hwid": "SIMULATED"}]

    def inspect(self, port: str, log: LogFn) -> DeviceInfo:
        if not self.connected:
            raise TransportError("Virtuelles USB-Kabel ist getrennt")
        log("Virtueller ESP32-C3 erkannt: 4 MiB, keine Sicherheitssperren")
        return DeviceInfo(
            port="VIRTUAL0",
            chip="ESP32-C3",
            mac="02:00:00:00:00:01",
            flash_size=len(self.memory),
            security=SecurityInfo(),
            virtual=True,
            profile_hint="virtual-ir-tracker",
        )

    def read_flash(self, device: DeviceInfo, destination: Path, log: LogFn) -> None:
        if not self.connected:
            raise TransportError("Virtuelles USB-Kabel ist getrennt")
        destination.write_bytes(self.memory)
        log(f"Virtuellen Flash gelesen: {len(self.memory)} Byte")

    def verify_backup(self, device: DeviceInfo, backup: Path, log: LogFn) -> None:
        if not self.connected:
            raise TransportError("Virtuelles USB-Kabel ist getrennt")
        if backup.read_bytes() != bytes(self.memory):
            raise TransportError("Virtuelles Backup stimmt nicht mit dem Flash überein")
        log("Virtuelles Backup bytegenau verifiziert")

    def flash(
        self, device: DeviceInfo, writes: list[tuple[int, Path]], log: LogFn
    ) -> None:
        if not self.connected:
            raise TransportError("Virtuelles USB-Kabel ist getrennt")
        log("Simulation der BIN-Installation gestartet")
        for offset, path in writes:
            payload = path.read_bytes()
            if offset < 0 or offset + len(payload) > len(self.memory):
                raise TransportError("Schreibbereich liegt außerhalb des virtuellen Flashs")
            self.memory[offset : offset + len(payload)] = payload
            log(f"Virtuell geschrieben: {path.name} bei {offset:#x}")
        self.flashed = True
        self.firmware = "custom"
        log("Virtueller Schreibvorgang verifiziert")

    def restore(self, device: DeviceInfo, backup: Path, log: LogFn) -> None:
        if not self.connected:
            raise TransportError("Virtuelles USB-Kabel ist getrennt")
        payload = backup.read_bytes()
        if len(payload) != len(self.memory):
            raise TransportError("Backupgröße passt nicht zum virtuellen ESP")
        self.memory[:] = payload
        self.flashed = False
        self.firmware = "solakon-original"
        log("Virtueller Originalzustand wiederhergestellt")

    def scan_rx(
        self,
        log: LogFn,
        progress: Callable[[dict[str, object]], None] | None = None,
    ) -> dict[str, int]:
        if not self.flashed:
            raise TransportError("Custom firmware is not installed")
        rates = tuple(dict.fromkeys((self.baud, 9600, 19200, 38400, 115200)))
        tested = 0
        total = 11 * len(rates)
        for pin in range(11):
            for baud in rates:
                if progress:
                    progress({
                        "active": True,
                        "complete": False,
                        "tested": tested,
                        "total": total,
                        "current_pin": pin,
                        "current_baud": baud,
                    })
                log(f"Simulation testet GPIO {pin} mit {baud} Baud")
                time.sleep(0.06)
                tested += 1
                if pin == self.rx_pin and baud == self.baud:
                    if progress:
                        progress({
                            "active": False,
                            "complete": True,
                            "found": True,
                            "tested": tested,
                            "total": total,
                            "current_pin": pin,
                            "current_baud": baud,
                            "found_pin": pin,
                            "found_baud": baud,
                        })
                    log(
                        "Simulation: frisches SML-Telegramm mit gültiger CRC "
                        f"nach {tested} Kombinationen gefunden"
                    )
                    return {"pin": pin, "baud": baud}
        raise TransportError(
            "Simulation: kein gültiges SML-Telegramm auf GPIO 0 bis 10"
        )

    def simulated_tracker_status(self) -> dict[str, object]:
        phase_power = (156.0, 142.0, 122.0)
        phase_voltage = (230.4, 231.1, 229.8)
        return {
            "firmware": "offline-simulation",
            "meter_fresh": True,
            "last_crc_valid": True,
            "power_w": sum(phase_power),
            "import_kwh": 1234.567,
            "export_kwh": 12.345,
            "phases": [
                {
                    "phase": f"L{index + 1}",
                    "power_w": phase_power[index],
                    "voltage_v": phase_voltage[index],
                    "current_a": round(phase_power[index] / phase_voltage[index], 3),
                }
                for index in range(3)
            ],
            "telegrams": 128,
            "received_bytes": 32768,
            "parse_errors": 0,
            "crc_errors": 0,
            "rx_gpio": self.rx_pin,
            "tx_gpio": self.tx_pin,
            "led_gpio": self.led_pin,
            "baud": self.baud,
        }

    def test_output(self, kind: str, pin: int, log: LogFn) -> bool:
        if not self.flashed:
            raise TransportError("Custom firmware is not installed")
        expected = self.led_pin if kind == "led" else self.tx_pin
        matched = pin == expected
        log(f"Virtueller {kind}-Test auf GPIO {pin}: {'sichtbar' if matched else 'keine Reaktion'}")
        return matched

    def set_connected(self, connected: bool, log: LogFn) -> None:
        self.connected = connected
        log("Virtuelles USB-Kabel verbunden" if connected else "Virtuelles USB-Kabel getrennt")

    def set_simulation_gpio(
        self, rx: int, tx: int, led: int, baud: int, log: LogFn
    ) -> None:
        pins = (rx, tx, led)
        if any(not 0 <= pin <= 21 for pin in pins) or len(set(pins)) != 3:
            raise TransportError("Simulierte RX-, TX- und LED-Pins müssen verschieden und zwischen 0 und 21 sein")
        if baud not in {2400, 4800, 9600, 19200, 38400, 57600, 115200}:
            raise TransportError("Ungültige simulierte Baudrate")
        self.rx_pin, self.tx_pin, self.led_pin = pins
        self.baud = baud
        log(f"Simulation eingestellt: RX {rx}, TX {tx}, LED {led}, {baud} Baud")

    def runtime_status(self) -> dict[str, object]:
        labels = {
            "solakon-original": "Solakon Original",
            "custom": "IR Tracker Custom",
        }
        return {
            "transport": "virtual-usb",
            "connected": self.connected,
            "firmware": self.firmware,
            "firmware_label": labels.get(self.firmware, self.firmware),
            "simulated_ip": self.simulated_ip,
            "simulated_gpio": {
                "rx": self.rx_pin,
                "tx": self.tx_pin,
                "led": self.led_pin,
                "baud": self.baud,
            },
        }
