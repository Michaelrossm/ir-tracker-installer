from __future__ import annotations

import unittest
from unittest.mock import ANY, patch

from installer.transport import RealEspTransport, TransportError


FLASH_ID = """
Chip type:          ESP32-D0WDQ6 (revision v1.0)
MAC:                c8:c9:a3:c4:c3:08
Detected flash size: 4MB
"""

CLASSIC_EFUSES = """
FLASH_CRYPT_CNT (BLOCK0) Flash encryption is enabled if odd = 0 R/W (0b0000000)
UART_DOWNLOAD_DIS (BLOCK0) Disable UART download mode = False R/W (0b0)
ABS_DONE_0 (BLOCK0) Secure boot V1 is enabled = False R/W (0b0)
ABS_DONE_1 (BLOCK0) Secure boot V2 is enabled = False R/W (0b0)
"""


class RealTransportTests(unittest.TestCase):
    def test_classic_esp32_uses_read_only_efuse_fallback(self) -> None:
        transport = RealEspTransport()
        with patch.object(
            transport,
            "_run",
            side_effect=[FLASH_ID, TransportError("Command not implemented")],
        ), patch.object(
            transport, "_read_efuse_summary", return_value=CLASSIC_EFUSES
        ) as efuse:
            device = transport.inspect("COM5", lambda _: None)
        efuse.assert_called_once_with("COM5", ANY)
        self.assertEqual(device.chip, "ESP32-D0WDQ6 (revision v1.0)")
        self.assertEqual(device.flash_size, 4 * 1024 * 1024)
        self.assertFalse(device.security.secure_boot)
        self.assertFalse(device.security.flash_encryption)
        self.assertFalse(device.security.secure_download_mode)


if __name__ == "__main__":
    unittest.main()
