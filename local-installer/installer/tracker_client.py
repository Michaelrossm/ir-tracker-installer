from __future__ import annotations

import base64
import ipaddress
import json
import math
import secrets
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class TrackerClientError(RuntimeError):
    pass


_HOME_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_MAX_RESPONSE = 256 * 1024


def _number(value: Any, minimum: float, maximum: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) and minimum <= result <= maximum else None


def _integer(value: Any, minimum: int, maximum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if minimum <= value <= maximum else None


def normalize_tracker_status(status: Any) -> dict[str, Any]:
    if not isinstance(status, dict):
        raise TrackerClientError("Antwort stammt nicht von einer unterstützten IR-Tracker-Firmware")
    firmware = status.get("firmware")
    if (
        not isinstance(firmware, str)
        or not firmware.startswith("offline-")
        or len(firmware) > 80
    ):
        raise TrackerClientError("Antwort stammt nicht von einer unterstützten IR-Tracker-Firmware")
    phases = status.get("phases") if isinstance(status.get("phases"), list) else []
    normalized_phases = []
    for index in range(3):
        phase = phases[index] if index < len(phases) and isinstance(phases[index], dict) else {}
        normalized_phases.append(
            {
                "phase": f"L{index + 1}",
                "power_w": _number(phase.get("power_w"), -100_000, 100_000),
                "voltage_v": _number(phase.get("voltage_v"), 0, 500),
                "current_a": _number(phase.get("current_a"), 0, 200),
            }
        )
    return {
        "firmware": firmware,
        "meter_fresh": status.get("meter_fresh") is True,
        "last_crc_valid": status.get("last_crc_valid") is True,
        "power_w": _number(status.get("power_w"), -100_000, 100_000),
        "import_kwh": _number(status.get("import_kwh"), 0, 1_000_000_000),
        "export_kwh": _number(status.get("export_kwh"), 0, 1_000_000_000),
        "phases": normalized_phases,
        "telegrams": _integer(status.get("telegrams"), 0, 4_294_967_295),
        "received_bytes": _integer(status.get("received_bytes"), 0, 4_294_967_295),
        "parse_errors": _integer(status.get("parse_errors"), 0, 4_294_967_295),
        "crc_errors": _integer(status.get("crc_errors"), 0, 4_294_967_295),
        "rx_gpio": _integer(status.get("rx_gpio"), -1, 48),
        "tx_gpio": _integer(status.get("tx_gpio"), -1, 48),
        "led_gpio": _integer(status.get("led_gpio"), -1, 48),
        "baud": _integer(status.get("baud"), 300, 1_000_000),
        "installer_wifi_ota": status.get("installer_wifi_ota") is True,
        "installer_gpio_tx_scan": status.get("installer_gpio_tx_scan") is True,
    }


def validate_tracker_ip(value: str) -> str:
    """Accept only literal RFC1918 IPv4 addresses; never arbitrary URLs/hosts."""
    candidate = value.strip()
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as error:
        raise TrackerClientError("Bitte eine gültige private IPv4-Adresse eingeben") from error
    if address.version != 4 or not any(address in network for network in _HOME_NETWORKS):
        raise TrackerClientError(
            "Nur private IPv4-Adressen aus dem Heimnetz (10.x, 172.16–31.x oder 192.168.x) sind erlaubt"
        )
    return str(address)


def fetch_tracker_status(
    ip: str, admin_password: str = "", timeout: float = 4.0
) -> dict[str, Any]:
    safe_ip = validate_tracker_ip(ip)
    request = Request(
        f"http://{safe_ip}/api/v1/status",
        headers={"Accept": "application/json", "Cache-Control": "no-store"},
        method="GET",
    )
    if admin_password:
        credentials = base64.b64encode(
            f"admin:{admin_password}".encode("utf-8")
        ).decode("ascii")
        request.add_header("Authorization", f"Basic {credentials}")
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise TrackerClientError(f"Tracker antwortet mit HTTP {response.status}")
            content_type = response.headers.get_content_type()
            if content_type != "application/json":
                raise TrackerClientError("Tracker liefert keine JSON-Statusdaten")
            payload = response.read(_MAX_RESPONSE + 1)
    except HTTPError as error:
        if error.code == 401:
            raise TrackerClientError(
                "Tracker-API verlangt die optionale Admin-Anmeldung"
            ) from error
        if error.code == 404:
            raise TrackerClientError(
                "Status-API ist deaktiviert oder diese Firmware unterstützt sie nicht"
            ) from error
        raise TrackerClientError(f"Tracker antwortet mit HTTP {error.code}") from error
    except (URLError, TimeoutError, OSError) as error:
        raise TrackerClientError(
            "Tracker ist unter dieser IP nicht erreichbar; WLAN und Adresse prüfen"
        ) from error
    if len(payload) > _MAX_RESPONSE:
        raise TrackerClientError("Statusantwort des Trackers ist unerwartet groß")
    try:
        status = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TrackerClientError("Statusantwort des Trackers ist beschädigt") from error
    return normalize_tracker_status(status)


def _admin_json_request(
    ip: str,
    path: str,
    admin_password: str,
    *,
    method: str = "GET",
    csrf_token: str = "",
    timeout: float = 5.0,
) -> dict[str, Any]:
    safe_ip = validate_tracker_ip(ip)
    if not admin_password:
        raise TrackerClientError(
            "Fuer die echte GPIO-Suche bitte das Admin-Passwort des Trackers eingeben"
        )
    credentials = base64.b64encode(
        f"admin:{admin_password}".encode("utf-8")
    ).decode("ascii")
    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {credentials}",
        "Cache-Control": "no-store",
    }
    if csrf_token:
        headers["X-CSRF-Token"] = csrf_token
    request = Request(
        f"http://{safe_ip}{path}",
        data=b"" if method == "POST" else None,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read(64 * 1024 + 1)
            if response.status not in {200, 202}:
                raise TrackerClientError(
                    f"Tracker antwortet mit HTTP {response.status}"
                )
    except HTTPError as error:
        if error.code == 401:
            raise TrackerClientError("Admin-Passwort des Trackers ist falsch") from error
        if error.code == 403:
            raise TrackerClientError("Sicherheitsfreigabe fuer die GPIO-Suche wurde abgelehnt") from error
        if error.code == 404:
            raise TrackerClientError(
                "Diese Tracker-Firmware besitzt noch keine echte GPIO-Suche; zuerst die neue Custom-Firmware installieren"
            ) from error
        raise TrackerClientError(f"Tracker antwortet mit HTTP {error.code}") from error
    except (URLError, TimeoutError, OSError) as error:
        raise TrackerClientError("Verbindung zur GPIO-Suche wurde unterbrochen") from error
    if len(payload) > 64 * 1024:
        raise TrackerClientError("GPIO-Suchantwort ist unerwartet gross")
    try:
        result = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TrackerClientError("GPIO-Suchantwort ist beschaedigt") from error
    if not isinstance(result, dict):
        raise TrackerClientError("GPIO-Suchantwort hat ein ungueltiges Format")
    return result


def scan_tracker_gpio(
    ip: str,
    admin_password: str,
    progress: Callable[[dict[str, Any]], None] | None = None,
    timeout: float = 140.0,
) -> dict[str, int]:
    """Run the firmware's non-persistent, CRC-verified RX scan and poll it."""
    session = _admin_json_request(ip, "/api/v1/admin-session", admin_password)
    csrf = session.get("csrf_token")
    if not isinstance(csrf, str) or len(csrf) != 64:
        raise TrackerClientError("Tracker lieferte keine gueltige Sicherheitsfreigabe")
    state = _admin_json_request(
        ip,
        "/api/v1/gpio-scan/start",
        admin_password,
        method="POST",
        csrf_token=csrf,
    )
    deadline = time.monotonic() + timeout
    while True:
        if progress:
            progress(state)
        if state.get("complete") is True:
            if state.get("found") is not True:
                raise TrackerClientError(
                    "Kein CRC-gueltiges SML-Telegramm auf GPIO 0 bis 10 gefunden"
                )
            pin = _integer(state.get("found_pin"), 0, 10)
            baud = _integer(state.get("found_baud"), 300, 1_000_000)
            if pin is None or baud is None:
                raise TrackerClientError("GPIO-Suchergebnis ist unvollstaendig")
            return {"pin": pin, "baud": baud}
        if time.monotonic() >= deadline:
            try:
                _admin_json_request(
                    ip,
                    "/api/v1/gpio-scan/cancel",
                    admin_password,
                    method="POST",
                    csrf_token=csrf,
                )
            except TrackerClientError:
                pass
            raise TrackerClientError("GPIO-Suche wurde nach 140 Sekunden abgebrochen")
        time.sleep(0.35)
        state = _admin_json_request(ip, "/api/v1/gpio-scan", admin_password)


def scan_tracker_tx(
    ip: str, admin_password: str, rx_pin: int, timeout: float = 20.0
) -> dict[str, int | bool]:
    """Find TX through repeated optical loopback correlation at a confirmed RX."""
    if not isinstance(rx_pin, int) or isinstance(rx_pin, bool) or not 0 <= rx_pin <= 10:
        raise TrackerClientError("Zuerst einen gültigen RX-Pin bestätigen")
    session = _admin_json_request(ip, "/api/v1/admin-session", admin_password)
    csrf = session.get("csrf_token")
    if not isinstance(csrf, str) or len(csrf) != 64:
        raise TrackerClientError("Tracker lieferte keine gültige Sicherheitsfreigabe")
    result = _admin_json_request(
        ip, f"/api/v1/gpio-scan-tx?rx={rx_pin}", admin_password,
        method="POST", csrf_token=csrf, timeout=timeout,
    )
    if result.get("complete") is not True or result.get("found") is not True:
        raise TrackerClientError(
            "Kein eindeutiger optischer TX-Rückkanal gefunden; Lesekopf ausrichten oder manuell prüfen"
        )
    pin = _integer(result.get("pin"), 0, 10)
    confidence = _integer(result.get("confidence"), 0, 100)
    tested = _integer(result.get("tested"), 1, 10)
    active = _integer(result.get("active_transitions"), 0, 65535)
    idle = _integer(result.get("idle_transitions"), 0, 65535)
    if pin is None or pin == rx_pin or confidence is None or tested is None:
        raise TrackerClientError("Automatisches TX-Suchergebnis ist unvollständig")
    return {
        "pin": pin,
        "inverted": result.get("inverted") is True,
        "confidence": confidence,
        "tested": tested,
        "active_transitions": active or 0,
        "idle_transitions": idle or 0,
    }


def test_tracker_output(
    ip: str,
    admin_password: str,
    pin: int,
    *,
    inverted: bool = False,
    allow_configured_fallback: bool = False,
) -> dict[str, int | bool | str]:
    """Send one short, non-persistent pulse on a candidate output GPIO."""
    if not isinstance(pin, int) or isinstance(pin, bool) or not 0 <= pin <= 10:
        raise TrackerClientError("Ausgangs-GPIO muss zwischen 0 und 10 liegen")
    session = _admin_json_request(ip, "/api/v1/admin-session", admin_password)
    csrf = session.get("csrf_token")
    if not isinstance(csrf, str) or len(csrf) != 64:
        raise TrackerClientError("Tracker lieferte keine gültige Sicherheitsfreigabe")
    mode = "candidate_gpio"
    try:
        result = _admin_json_request(
            ip,
            f"/api/v1/gpio-output-test?pin={pin}&inverted={1 if inverted else 0}",
            admin_password,
            method="POST",
            csrf_token=csrf,
        )
    except TrackerClientError:
        if not allow_configured_fallback:
            raise
        result = _admin_json_request(
            ip,
            f"/ir/pulse?inverted={1 if inverted else 0}",
            admin_password,
            method="POST",
            csrf_token=csrf,
        )
        mode = "configured_tx_fallback"
        if result.get("accepted") is True and result.get("pulses") == 1:
            result = {"accepted": True, "pin": pin, "duration_ms": 300}
    if result.get("accepted") is not True or result.get("pin") != pin:
        raise TrackerClientError("Tracker hat den Ausgangstest nicht bestätigt")
    duration = _integer(result.get("duration_ms"), 50, 2000)
    if duration is None:
        raise TrackerClientError("Antwort des Ausgangstests ist unvollständig")
    return {
        "accepted": True, "pin": pin, "duration_ms": duration, "mode": mode,
    }


def install_tracker_firmware(
    ip: str,
    admin_password: str,
    filename: str,
    package: bytes,
    progress: Callable[[str, float], None] | None = None,
    timeout: float = 90.0,
) -> None:
    """Upload one signed app package to the tracker's OTA app slot."""
    safe_ip = validate_tracker_ip(ip)
    safe_name = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if not safe_name.lower().endswith(".irfw"):
        raise TrackerClientError("WLAN-Updates akzeptieren ausschliesslich signierte .irfw-Pakete")
    if not 1024 <= len(package) <= 4 * 1024 * 1024:
        raise TrackerClientError("Firmwarepaket hat eine unzulaessige Groesse")
    if progress:
        progress("Sicherheitsfreigabe vom Tracker anfordern", 15.0)
    session = _admin_json_request(safe_ip, "/api/v1/admin-session", admin_password)
    csrf = session.get("csrf_token")
    if not isinstance(csrf, str) or len(csrf) != 64:
        raise TrackerClientError("Tracker lieferte keine gueltige Sicherheitsfreigabe")

    boundary = "----IRTrackerInstaller" + secrets.token_hex(16)
    prefix = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="firmware"; filename="{safe_name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("ascii")
    suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
    body = prefix + package + suffix
    credentials = base64.b64encode(
        f"admin:{admin_password}".encode("utf-8")
    ).decode("ascii")
    request = Request(
        f"http://{safe_ip}/system/update",
        data=body,
        headers={
            "Authorization": f"Basic {credentials}",
            "X-CSRF-Token": csrf,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
            "Accept": "text/html",
            "Cache-Control": "no-store",
        },
        method="POST",
    )
    if progress:
        progress("Signierte Custom-App ueber WLAN uebertragen", 40.0)
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read(64 * 1024 + 1)
            if response.status != 200:
                raise TrackerClientError(f"Tracker antwortet mit HTTP {response.status}")
    except HTTPError as error:
        if error.code == 401:
            raise TrackerClientError("Admin-Passwort des Trackers ist falsch") from error
        if error.code == 403:
            raise TrackerClientError("Sicherheitsfreigabe fuer das WLAN-Update wurde abgelehnt") from error
        if error.code == 400:
            raise TrackerClientError("Tracker hat Signatur oder Firmwarepaket abgelehnt") from error
        raise TrackerClientError(f"Tracker antwortet mit HTTP {error.code}") from error
    except (URLError, TimeoutError, OSError) as error:
        raise TrackerClientError("WLAN-Update wurde vor der Bestaetigung unterbrochen") from error
    if len(payload) > 64 * 1024:
        raise TrackerClientError("Updateantwort des Trackers ist unerwartet gross")
    if progress:
        progress("Update angenommen; Tracker startet neu", 72.0)
