from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from installer.firmware import FirmwareError, store_firmware


ROOT = Path(__file__).resolve().parents[2]


class FirmwareTests(unittest.TestCase):
    def test_signed_irfw_is_verified_and_unwrapped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            selection = store_firmware(
                Path(directory),
                "firmware.irfw",
                (ROOT / "release" / "ir-tracker-custom-1.0.2-beta.1.irfw").read_bytes(),
                1376256,
                "ESP32-C3",
                ROOT / "signing" / "firmware-signing-public.pem",
                "local-signed",
            )
            self.assertTrue(selection.signed)
            self.assertTrue(selection.trusted)
            self.assertEqual(
                selection.size,
                (ROOT / "release" / "ir-tracker-custom-1.0.2-beta.1-usb.bin").stat().st_size,
            )
            self.assertEqual(selection.path.read_bytes()[0], 0xE9)

    def test_modified_signed_package_is_rejected(self) -> None:
        package = bytearray(
            (ROOT / "release" / "ir-tracker-custom-1.0.2-beta.1.irfw").read_bytes()
        )
        package[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(FirmwareError):
            store_firmware(
                Path(directory),
                "firmware.irfw",
                bytes(package),
                1376256,
                "ESP32-C3",
                ROOT / "signing" / "firmware-signing-public.pem",
                "local-signed",
            )

    def test_wrong_esp_chip_is_rejected(self) -> None:
        firmware = bytearray(
            (ROOT / "release" / "ir-tracker-custom-1.0.2-beta.1-usb.bin").read_bytes()
        )
        firmware[12:14] = (0).to_bytes(2, "little")
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(FirmwareError):
            store_firmware(
                Path(directory),
                "firmware.bin",
                bytes(firmware),
                1376256,
                "ESP32-C3",
                ROOT / "signing" / "firmware-signing-public.pem",
                "local-unsigned",
            )
