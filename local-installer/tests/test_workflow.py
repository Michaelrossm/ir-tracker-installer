from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from installer.profiles import ProfileStore
from installer.transport import TransportError, VirtualEspTransport
from installer.workflow import InstallerWorkflow, WorkflowError


ROOT = Path(__file__).resolve().parents[2]


class ProfilePinTransport(VirtualEspTransport):
    def scan_rx(self, log, progress=None):
        raise TransportError("Kein universelles Scan-Protokoll")


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.transport = VirtualEspTransport()
        self.workflow = InstallerWorkflow(
            workspace=ROOT,
            transport=self.transport,
            profile_store=ProfileStore(ROOT / "local-installer" / "profiles"),
            backup_root=Path(self.temp.name),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_flash_is_impossible_before_verified_backup(self) -> None:
        self.workflow.select("VIRTUAL0")
        self.workflow.inspect()
        with self.assertRaises(WorkflowError):
            self.workflow.flash("BACKUP OK")

    def test_complete_virtual_installation(self) -> None:
        self.assertEqual(
            self.workflow.status()["runtime"]["firmware"], "solakon-original"
        )
        self.workflow.select("VIRTUAL0")
        inspected = self.workflow.inspect()
        self.assertEqual(inspected["device"]["flash_size"], 4 * 1024 * 1024)
        backed_up = self.workflow.backup()
        self.assertEqual(backed_up["stage"], "compatible")
        self.assertTrue(backed_up["compatibility"]["compatible"])
        self.assertEqual(backed_up["operation"]["percent"], 100.0)
        self.assertFalse(backed_up["operation"]["running"])
        flashed = self.workflow.flash("BACKUP OK")
        self.assertEqual(flashed["stage"], "flashed")
        self.assertEqual(flashed["runtime"]["firmware"], "custom")
        self.workflow.connect_tracker("192.168.4.1")
        scanned = self.workflow.scan_rx()
        self.assertEqual(scanned["gpio"]["rx"], 3)
        self.assertEqual(scanned["operation"]["details"]["found_pin"], 3)
        self.assertGreater(scanned["operation"]["details"]["tested"], 0)
        self.assertGreater(scanned["operation"]["details"]["total"], 0)
        self.assertTrue(any("IR-Eingang eindeutig gefunden" in line for line in scanned["logs"]))
        self.assertTrue(any("Nachweisregel" in line for line in scanned["logs"]))
        self.assertTrue(self.workflow.test_output("led", 5)["visible"])
        self.workflow.confirm_output("led", 5)
        self.assertTrue(self.workflow.test_output("tx", 6)["visible"])
        complete = self.workflow.confirm_output("tx", 6)
        self.assertEqual(complete["stage"], "complete")

        restored = self.workflow.restore("ORIGINAL WIEDERHERSTELLEN")
        self.assertEqual(restored["stage"], "inspected")
        self.assertEqual(restored["runtime"]["firmware"], "solakon-original")
        self.assertFalse(self.transport.flashed)

    def test_virtual_ip_and_configurable_simulation_pins(self) -> None:
        runtime = self.workflow.status()["runtime"]
        self.assertEqual(runtime["simulated_ip"], "192.168.4.1")
        configured = self.workflow.configure_virtual_gpio(8, 9, 10, 19200)
        self.assertEqual(
            configured["runtime"]["simulated_gpio"],
            {"rx": 8, "tx": 9, "led": 10, "baud": 19200},
        )
        self.workflow.select("VIRTUAL0")
        self.workflow.inspect()
        self.workflow.backup()
        self.workflow.flash("BACKUP OK")
        self.workflow.connect_tracker("192.168.4.1")
        scanned = self.workflow.scan_rx()
        self.assertEqual(scanned["gpio"]["rx"], 8)
        self.assertEqual(scanned["gpio"]["baud"], 19200)
        self.assertNotIn("tx", scanned["gpio"])
        self.assertNotIn("led", scanned["gpio"])
        self.assertTrue(self.workflow.test_output("tx", 9)["visible"])

    def test_virtual_usb_disconnect_and_reconnect(self) -> None:
        disconnected = self.workflow.set_virtual_usb(False)
        self.assertFalse(disconnected["runtime"]["connected"])
        self.assertEqual(self.transport.list_ports(), [])
        self.workflow.select("VIRTUAL0")
        with self.assertRaises(TransportError):
            self.workflow.inspect()
        connected = self.workflow.set_virtual_usb(True)
        self.assertTrue(connected["runtime"]["connected"])
        self.assertEqual(self.transport.list_ports()[0]["port"], "VIRTUAL0")

    def test_wrong_confirmation_does_not_flash(self) -> None:
        self.workflow.select("VIRTUAL0")
        self.workflow.inspect()
        self.workflow.backup()
        with self.assertRaises(WorkflowError):
            self.workflow.flash("JA")
        self.assertFalse(self.transport.flashed)

    def test_profile_is_never_misrepresented_as_a_real_gpio_scan(self) -> None:
        workflow = InstallerWorkflow(
            workspace=ROOT,
            transport=ProfilePinTransport(),
            profile_store=ProfileStore(ROOT / "local-installer" / "profiles"),
            backup_root=Path(self.temp.name),
        )
        workflow.select("VIRTUAL0")
        workflow.inspect()
        workflow.backup()
        workflow.flash("BACKUP OK")
        workflow.connect_tracker("192.168.4.1")
        with self.assertRaisesRegex(WorkflowError, "Kein universelles Scan-Protokoll"):
            workflow.scan_rx()

    def test_existing_backup_can_be_verified_and_loaded_after_restart(self) -> None:
        self.workflow.select("VIRTUAL0")
        self.workflow.inspect()
        self.workflow.backup()
        backup_id = Path(self.workflow.manifest.backup_file).parts[0]
        restarted = InstallerWorkflow(
            workspace=ROOT,
            transport=self.transport,
            profile_store=ProfileStore(ROOT / "local-installer" / "profiles"),
            backup_root=Path(self.temp.name),
        )
        restarted.select("VIRTUAL0")
        restarted.inspect()
        catalog = restarted.list_backups()
        self.assertEqual(catalog[0]["id"], backup_id)
        self.assertTrue(catalog[0]["available"])
        loaded = restarted.load_backup(backup_id)
        self.assertEqual(loaded["stage"], "compatible")
        self.assertEqual(loaded["backup"]["size"], 4 * 1024 * 1024)

    def test_unsigned_local_bin_requires_stronger_confirmation(self) -> None:
        self.workflow.select("VIRTUAL0")
        self.workflow.inspect()
        self.workflow.backup()
        selected = self.workflow.select_local_firmware(
            "custom.bin",
            (ROOT / "release" / "ir-tracker-custom-1.0.2-beta.1-usb.bin").read_bytes(),
        )
        self.assertEqual(selected["firmware_selection"]["source"], "local-unsigned")
        with self.assertRaises(WorkflowError):
            self.workflow.flash("BACKUP OK")
        flashed = self.workflow.flash("UNSIGNIERTE BIN")
        self.assertEqual(flashed["stage"], "flashed")


if __name__ == "__main__":
    unittest.main()
