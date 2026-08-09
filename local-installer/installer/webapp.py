from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from .profiles import ProfileStore
from .self_update import InstallerUpdate, check_installer_update, stage_installer_update
from .transport import RealEspTransport, TransportError, VirtualEspTransport
from .workflow import InstallerWorkflow, WorkflowError


class InstallerServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        workflow: InstallerWorkflow,
        ui: Path,
        root: Path | None = None,
    ):
        self.workflow = workflow
        self.ui = ui
        self.root = (root or workflow.workspace).resolve()
        self.simulation_roots: set[Path] = set()
        self._remember_simulation_root(workflow)
        self.token = secrets.token_urlsafe(32)
        self.installer_update = InstallerUpdate()
        super().__init__(address, InstallerHandler)

    def switch_mode(self, virtual: bool) -> dict[str, Any]:
        backup_root = self.workflow.persistent_backup_root
        self.workflow = make_workflow(self.root, virtual, backup_root)
        self._remember_simulation_root(self.workflow)
        self.workflow.log("Simulationsmodus gestartet" if virtual else "Echte USB-Hardware ausgewählt")
        return self.workflow.status()

    def _remember_simulation_root(self, workflow: InstallerWorkflow) -> None:
        simulation_base = (Path(tempfile.gettempdir()) / "IRTrackerInstaller").resolve()
        if workflow.backup_root.is_relative_to(simulation_base):
            self.simulation_roots.add(workflow.backup_root)

    def server_close(self) -> None:
        super().server_close()
        simulation_base = (Path(tempfile.gettempdir()) / "IRTrackerInstaller").resolve()
        for root in self.simulation_roots:
            if (
                root.is_relative_to(simulation_base)
                and root.name.startswith("simulation-")
                and root.is_dir()
            ):
                shutil.rmtree(root, ignore_errors=True)


class InstallerHandler(BaseHTTPRequestHandler):
    server: InstallerServer

    def log_message(self, fmt: str, *args: Any) -> None:
        if urlparse(self.path).path in {"/api/status", "/api/tracker/status"}:
            return
        self.server.workflow.log("HTTP " + (fmt % args))

    def _security_headers(self) -> None:
        """Apply consistent local-browser hardening to every response."""
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )

    def _json(self, value: Any, status: int = 200) -> None:
        payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._security_headers()
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _download(self, filename: str, payload: bytes, content_type: str) -> None:
        safe_name = "".join(
            character for character in filename if character.isalnum() or character in "._-"
        )
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
        self._security_headers()
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise WorkflowError("Ungültige Anfragegröße") from error
        if length < 0 or length > 16_384:
            raise WorkflowError("Anfrage ist zu groß")
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise WorkflowError("Ungültige JSON-Anfrage") from error

    def _raw_body(self, maximum: int) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise WorkflowError("Ungültige Dateigröße") from error
        if length <= 0 or length > maximum:
            raise WorkflowError(f"Firmwaredatei muss zwischen 1 und {maximum} Byte groß sein")
        payload = self.rfile.read(length)
        if len(payload) != length:
            raise WorkflowError("Firmwaredatei wurde nicht vollständig übertragen")
        return payload

    def _check_token(self) -> None:
        if not secrets.compare_digest(
            self.headers.get("X-Installer-Token", ""), self.server.token
        ):
            raise WorkflowError("Ungültiges Sitzungstoken")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/api/status":
                # Status remains available while a long USB operation owns the workflow lock.
                self._json(self.server.workflow.status())
                return
            if path == "/api/ports":
                self._json({"ports": self.server.workflow.transport.list_ports()})
                return
            if path == "/":
                html = self.server.ui.read_text(encoding="utf-8").replace(
                    "__INSTALLER_TOKEN__", self.server.token
                )
                payload = html.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
                self._security_headers()
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_error(HTTPStatus.NOT_FOUND)
        except (WorkflowError, TransportError, OSError) as error:
            self._json({"error": str(error)}, 409)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            self._check_token()
            workflow = self.server.workflow
            if path == "/api/firmware/upload":
                filename = unquote(self.headers.get("X-Firmware-Filename", ""))
                if not filename or len(filename) > 240:
                    raise WorkflowError("Firmware-Dateiname fehlt oder ist zu lang")
                payload = self._raw_body(4 * 1024 * 1024)
                with workflow.lock:
                    result = workflow.select_local_firmware(filename, payload)
                self._json(result)
                return
            if path == "/api/tracker/wifi-update":
                filename = unquote(self.headers.get("X-Firmware-Filename", ""))
                if not filename or len(filename) > 240:
                    raise WorkflowError("Firmware-Dateiname fehlt oder ist zu lang")
                payload = self._raw_body(4 * 1024 * 1024)
                with workflow.lock:
                    result = workflow.wifi_update(filename, payload)
                self._json(result)
                return
            body = self._body()
            with workflow.lock:
                if path == "/api/mode":
                    result = self.server.switch_mode(bool(body.get("virtual", False)))
                elif path == "/api/virtual/usb":
                    result = workflow.set_virtual_usb(bool(body.get("connected", False)))
                elif path == "/api/virtual/config":
                    result = workflow.configure_virtual_gpio(
                        int(body.get("rx", -1)), int(body.get("tx", -1)),
                        int(body.get("led", -1)), int(body.get("baud", 0)),
                    )
                elif path == "/api/select":
                    result = workflow.select(str(body.get("port", "")))
                elif path == "/api/inspect":
                    result = workflow.inspect()
                elif path == "/api/backup":
                    result = workflow.backup()
                elif path == "/api/backups/list":
                    result = {"backups": workflow.list_backups()}
                elif path == "/api/backups/open-folder":
                    result = workflow.open_backup_folder()
                elif path == "/api/backups/load":
                    result = workflow.load_backup(str(body.get("id", "")))
                elif path == "/api/backups/bin":
                    filename, payload = workflow.backup_binary()
                    self._download(filename, payload, "application/octet-stream")
                    return
                elif path == "/api/backups/report":
                    filename, payload = workflow.backup_report()
                    self._download(filename, payload, "application/json; charset=utf-8")
                    return
                elif path == "/api/flash":
                    result = workflow.flash(str(body.get("confirmation", "")))
                elif path == "/api/firmware/github":
                    result = workflow.select_github_firmware()
                elif path == "/api/installer-update/check":
                    self.server.installer_update = check_installer_update()
                    result = self.server.installer_update.public()
                elif path == "/api/installer-update/download":
                    update_root = workflow.persistent_backup_root.parent / "updates"
                    self.server.installer_update = stage_installer_update(
                        self.server.installer_update, update_root
                    )
                    result = self.server.installer_update.public()
                elif path == "/api/shutdown":
                    result = {"stopping": True}
                    threading.Timer(0.15, self.server.shutdown).start()
                elif path == "/api/gpio/scan-rx":
                    result = workflow.scan_rx()
                elif path == "/api/gpio/scan-tx":
                    result = workflow.scan_tx()
                elif path == "/api/gpio/test":
                    result = workflow.test_output(str(body.get("kind", "")), int(body.get("pin", -1)))
                elif path == "/api/gpio/confirm":
                    result = workflow.confirm_output(str(body.get("kind", "")), int(body.get("pin", -1)))
                elif path == "/api/tracker/connect":
                    result = workflow.connect_tracker(
                        str(body.get("ip", "")), str(body.get("admin_password", ""))
                    )
                elif path == "/api/tracker/status":
                    result = workflow.refresh_tracker()
                elif path == "/api/tracker/disconnect":
                    result = workflow.disconnect_tracker()
                elif path == "/api/restore":
                    result = workflow.restore(str(body.get("confirmation", "")))
                else:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
            self._json(result)
        except (WorkflowError, TransportError, OSError, ValueError, KeyError) as error:
            self.server.workflow.log("FEHLER: " + str(error))
            self._json({"error": str(error), "status": self.server.workflow.status()}, 409)
        except BaseException as error:
            if isinstance(error, (KeyboardInterrupt, GeneratorExit)):
                raise
            detail = f"{type(error).__name__}: {error}"
            self.server.workflow.log("INTERNER FEHLER: " + detail)
            self._json(
                {
                    "error": "Interner Fehler. Details stehen nur im lokalen Installer-Protokoll.",
                    "status": self.server.workflow.status(),
                },
                500,
            )


def make_workflow(
    root: Path, virtual: bool, backup_root: Path | None = None
) -> InstallerWorkflow:
    original_candidates = [
        Path.cwd() / "original bin" / "solakon-powertracker-original-full.bin",
        root / "original bin" / "solakon-powertracker-original-full.bin",
    ]
    if getattr(sys, "frozen", False):
        original_candidates.insert(
            0,
            Path(sys.executable).resolve().parent
            / "original bin"
            / "solakon-powertracker-original-full.bin",
        )
    original = next((item for item in original_candidates if item.is_file()), None)
    transport = VirtualEspTransport(original_image=original) if virtual else RealEspTransport()
    persistent_backup_root = backup_root
    effective_backup_root = backup_root
    if virtual and backup_root:
        effective_backup_root = (
            Path(tempfile.gettempdir())
            / "IRTrackerInstaller"
            / f"simulation-{os.getpid()}"
        )
    return InstallerWorkflow(
        workspace=root,
        transport=transport,
        profile_store=ProfileStore(root / "local-installer" / "profiles"),
        backup_root=effective_backup_root,
        firmware_cache=(effective_backup_root / ".firmware-cache") if effective_backup_root else None,
        persistent_backup_root=persistent_backup_root,
    )


def application_root() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS).resolve()
    return Path(__file__).resolve().parents[2]


def default_backup_root(root: Path) -> Path:
    if not getattr(sys, "frozen", False):
        return root / "device-backups" / "installer"
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "IRTrackerInstaller" / "backups"


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe local IR Tracker installer")
    parser.add_argument("--virtual", action="store_true", help="use a simulated ESP32-C3")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--port", type=int, default=0, help="local HTTP port; 0 selects a free port")
    args = parser.parse_args()
    root = application_root()
    workflow = make_workflow(root, args.virtual, default_backup_root(root))
    server = InstallerServer(
        ("127.0.0.1", args.port),
        workflow,
        root / "local-installer" / "ui" / "index.html",
        root,
    )
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"IR Tracker Installer: {url}")
    print("Nur lokal erreichbar. Mit Strg+C beenden.")
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
