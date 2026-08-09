from __future__ import annotations

import http.client
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from installer.profiles import ProfileStore
from installer.transport import VirtualEspTransport
from installer.webapp import InstallerServer
from installer.workflow import InstallerWorkflow


ROOT = Path(__file__).resolve().parents[2]


class WebAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        workflow = InstallerWorkflow(
            workspace=ROOT,
            transport=VirtualEspTransport(),
            profile_store=ProfileStore(ROOT / "local-installer" / "profiles"),
            backup_root=Path(self.temp.name),
        )
        self.server = InstallerServer(
            ("127.0.0.1", 0), workflow, ROOT / "local-installer" / "ui" / "index.html"
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method: str, path: str, body: dict | None = None, token: bool = True):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {}
        payload = None
        if body is not None:
            payload = json.dumps(body)
            headers["Content-Type"] = "application/json"
        if token:
            headers["X-Installer-Token"] = self.server.token
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        data = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, data

    def request_raw(self, path: str):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        connection.request(
            "POST",
            path,
            body=b"{}",
            headers={
                "Content-Type": "application/json",
                "X-Installer-Token": self.server.token,
            },
        )
        response = connection.getresponse()
        payload = response.read()
        headers = dict(response.getheaders())
        connection.close()
        return response.status, headers, payload

    def upload_firmware(self, filename: str, payload: bytes):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        connection.request(
            "POST",
            "/api/firmware/upload",
            body=payload,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Installer-Token": self.server.token,
                "X-Firmware-Filename": filename,
            },
        )
        response = connection.getresponse()
        data = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, data

    def upload_wifi_firmware(self, filename: str, payload: bytes):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        connection.request(
            "POST", "/api/tracker/wifi-update", body=payload,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Installer-Token": self.server.token,
                "X-Firmware-Filename": filename,
            },
        )
        response = connection.getresponse()
        data = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, data

    def test_post_requires_session_token(self) -> None:
        status, data = self.request("POST", "/api/select", {"port": "VIRTUAL0"}, token=False)
        self.assertEqual(status, 409)
        self.assertIn("Sitzungstoken", data["error"])

    def test_browser_security_headers_are_applied(self) -> None:
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=5
        )
        connection.request("GET", "/")
        response = connection.getresponse()
        response.read()
        headers = dict(response.getheaders())
        connection.close()
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertIn("camera=()", headers["Permissions-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_full_virtual_api_flow(self) -> None:
        for path, body, expected in (
            ("/api/select", {"port": "VIRTUAL0"}, "selected"),
            ("/api/inspect", {}, "inspected"),
            ("/api/backup", {}, "compatible"),
            ("/api/flash", {"confirmation": "BACKUP OK"}, "flashed"),
            ("/api/tracker/connect", {"ip": "192.168.4.1"}, "flashed"),
            ("/api/gpio/scan-rx", {}, "gpio"),
        ):
            status, data = self.request("POST", path, body)
            self.assertEqual(status, 200, data)
            self.assertEqual(data["stage"], expected)
        status, tested = self.request(
            "POST", "/api/gpio/test", {"kind": "led", "pin": 5}
        )
        self.assertEqual(status, 200, tested)
        status, data = self.request(
            "POST", "/api/gpio/confirm", {"kind": "led", "pin": 5}
        )
        self.assertEqual(data["stage"], "gpio")
        status, tested = self.request(
            "POST", "/api/gpio/test", {"kind": "tx", "pin": 6}
        )
        self.assertEqual(status, 200, tested)
        status, data = self.request(
            "POST", "/api/gpio/confirm", {"kind": "tx", "pin": 6}
        )
        self.assertEqual(data["stage"], "complete")
        self.assertEqual(data["runtime"]["firmware"], "custom")
        status, data = self.request(
            "POST",
            "/api/restore",
            {"confirmation": "ORIGINAL WIEDERHERSTELLEN"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["runtime"]["firmware"], "solakon-original")

    def test_virtual_usb_api(self) -> None:
        status, data = self.request(
            "POST", "/api/virtual/usb", {"connected": False}
        )
        self.assertEqual(status, 200)
        self.assertFalse(data["runtime"]["connected"])
        status, data = self.request(
            "POST", "/api/virtual/usb", {"connected": True}
        )
        self.assertEqual(status, 200)
        self.assertTrue(data["runtime"]["connected"])

    def test_virtual_gpio_configuration_api(self) -> None:
        status, data = self.request(
            "POST",
            "/api/virtual/config",
            {"rx": 8, "tx": 9, "led": 10, "baud": 19200},
        )
        self.assertEqual(status, 200, data)
        self.assertEqual(data["runtime"]["simulated_ip"], "192.168.4.1")
        self.assertEqual(data["runtime"]["simulated_gpio"]["rx"], 8)

    def test_output_cannot_be_confirmed_without_matching_test(self) -> None:
        self.request("POST", "/api/select", {"port": "VIRTUAL0"})
        self.request("POST", "/api/inspect", {})
        self.request("POST", "/api/backup", {})
        self.request("POST", "/api/flash", {"confirmation": "BACKUP OK"})
        self.request("POST", "/api/tracker/connect", {"ip": "192.168.4.1"})
        self.request("POST", "/api/gpio/scan-rx", {})
        status, data = self.request(
            "POST", "/api/gpio/confirm", {"kind": "tx", "pin": 6}
        )
        self.assertEqual(status, 409)
        self.assertIn("zuerst testen", data["error"])

    def test_tracker_wifi_status_api(self) -> None:
        self.request("POST", "/api/select", {"port": "VIRTUAL0"})
        self.request("POST", "/api/inspect", {})
        self.request("POST", "/api/backup", {})
        self.request("POST", "/api/flash", {"confirmation": "BACKUP OK"})
        status, data = self.request(
            "POST", "/api/tracker/connect", {"ip": "192.168.4.1"}
        )
        self.assertEqual(status, 200, data)
        self.assertTrue(data["tracker"]["online"])
        self.assertEqual(data["tracker"]["data"]["rx_gpio"], 3)
        status, data = self.request("POST", "/api/tracker/status", {})
        self.assertEqual(status, 200, data)
        self.assertEqual(data["tracker"]["data"]["tx_gpio"], 6)
        status, data = self.request("POST", "/api/tracker/disconnect", {})
        self.assertEqual(status, 200, data)
        self.assertIsNone(data["tracker"])

    def test_backup_catalog_and_verified_downloads(self) -> None:
        self.request("POST", "/api/select", {"port": "VIRTUAL0"})
        self.request("POST", "/api/inspect", {})
        status, backed_up = self.request("POST", "/api/backup", {})
        self.assertEqual(status, 200)
        status, catalog = self.request("POST", "/api/backups/list", {})
        self.assertEqual(status, 200)
        self.assertEqual(len(catalog["backups"]), 1)
        self.assertTrue(catalog["backups"][0]["available"])
        status, headers, payload = self.request_raw("/api/backups/bin")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload), 4 * 1024 * 1024)
        self.assertIn("attachment", headers["Content-Disposition"])
        status, _, report = self.request_raw("/api/backups/report")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(report)["sha256"], backed_up["backup"]["sha256"])

    def test_backup_progress_remains_live_during_long_operation(self) -> None:
        self.request("POST", "/api/select", {"port": "VIRTUAL0"})
        self.request("POST", "/api/inspect", {})
        transport = self.server.workflow.transport
        original_read = transport.read_flash

        def slow_read(device, destination, log):
            for percent in (10, 30, 55):
                log(f"Reading flash {percent}%")
                time.sleep(0.08)
            original_read(device, destination, log)

        transport.read_flash = slow_read
        result = {}

        def run_backup():
            result["response"] = self.request("POST", "/api/backup", {})

        worker = threading.Thread(target=run_backup)
        worker.start()
        time.sleep(0.12)
        status_code, live = self.request("GET", "/api/status", None)
        self.assertEqual(status_code, 200)
        self.assertTrue(live["operation"]["running"])
        self.assertGreater(live["operation"]["percent"], 1)
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result["response"][0], 200)

    def test_gpio_scan_progress_remains_visible_at_gpio_step(self) -> None:
        self.request(
            "POST", "/api/virtual/config",
            {"rx": 8, "tx": 9, "led": 10, "baud": 19200},
        )
        self.request("POST", "/api/select", {"port": "VIRTUAL0"})
        self.request("POST", "/api/inspect", {})
        self.request("POST", "/api/backup", {})
        self.request("POST", "/api/flash", {"confirmation": "BACKUP OK"})
        self.request("POST", "/api/tracker/connect", {"ip": "192.168.4.1"})
        result = {}

        def run_scan():
            result["response"] = self.request("POST", "/api/gpio/scan-rx", {})

        worker = threading.Thread(target=run_scan)
        worker.start()
        time.sleep(0.16)
        status_code, live = self.request("GET", "/api/status", None)
        self.assertEqual(status_code, 200)
        self.assertEqual(live["operation"]["name"], "gpio_scan")
        self.assertTrue(live["operation"]["running"])
        self.assertGreater(live["operation"]["details"]["total"], 0)
        self.assertIsNotNone(live["operation"]["details"]["current_pin"])
        worker.join(timeout=8)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result["response"][0], 200)
        finished = result["response"][1]["operation"]
        self.assertEqual(finished["details"]["found_pin"], 8)
        self.assertIn("Erfolg nach", finished["phase"])

    def test_virtual_tx_is_automatically_confirmed_after_rx(self) -> None:
        self.request("POST", "/api/select", {"port": "VIRTUAL0"})
        self.request("POST", "/api/inspect", {})
        self.request("POST", "/api/backup", {})
        self.request("POST", "/api/flash", {"confirmation": "BACKUP OK"})
        self.request("POST", "/api/tracker/connect", {"ip": "192.168.4.1"})
        self.request("POST", "/api/gpio/scan-rx", {})
        status, data = self.request("POST", "/api/gpio/scan-tx", {})
        self.assertEqual(status, 200, data)
        self.assertEqual(data["gpio"]["tx"], 6)
        self.assertEqual(data["operation"]["name"], "gpio_tx_scan")
        self.assertEqual(data["operation"]["percent"], 100)

    def test_signed_local_firmware_upload(self) -> None:
        self.request("POST", "/api/select", {"port": "VIRTUAL0"})
        self.request("POST", "/api/inspect", {})
        self.request("POST", "/api/backup", {})
        status, data = self.upload_firmware(
            "custom.irfw",
            (ROOT / "release" / "ir-tracker-custom-1.0.2-beta.1.irfw").read_bytes(),
        )
        self.assertEqual(status, 200, data)
        self.assertTrue(data["firmware_selection"]["signed"])
        self.assertTrue(data["firmware_selection"]["trusted"])

    def test_clean_shutdown_endpoint(self) -> None:
        status, data = self.request("POST", "/api/shutdown", {})
        self.assertEqual(status, 200)
        self.assertTrue(data["stopping"])

    def test_wifi_update_route_is_independent_of_usb_backup(self) -> None:
        self.server.workflow.tracker_ip = "192.168.178.66"
        self.server.workflow.tracker_password = "secret"
        self.server.workflow.tracker_snapshot = {"firmware": "offline-test"}
        called = {}

        def fake_update(filename, payload):
            called.update(filename=filename, payload=payload)
            return self.server.workflow.status()

        self.server.workflow.wifi_update = fake_update
        status, _ = self.upload_wifi_firmware("custom.irfw", b"signed-package")
        self.assertEqual(status, 200)
        self.assertEqual(called["filename"], "custom.irfw")
        self.assertEqual(called["payload"], b"signed-package")
        self.assertIsNone(self.server.workflow.manifest)


if __name__ == "__main__":
    unittest.main()
