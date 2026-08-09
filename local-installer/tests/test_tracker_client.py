from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

from installer.tracker_client import (
    TrackerClientError,
    fetch_tracker_status,
    install_tracker_firmware,
    scan_tracker_gpio,
    scan_tracker_tx,
    test_tracker_output,
    validate_tracker_ip,
)


class TrackerClientTests(unittest.TestCase):
    def test_accepts_only_literal_private_ipv4(self) -> None:
        self.assertEqual(validate_tracker_ip(" 192.168.178.66 "), "192.168.178.66")
        self.assertEqual(validate_tracker_ip("10.0.0.4"), "10.0.0.4")
        for value in ("127.0.0.1", "8.8.8.8", "tracker.local", "http://192.168.1.2"):
            with self.subTest(value=value), self.assertRaises(TrackerClientError):
                validate_tracker_ip(value)

    @patch("installer.tracker_client.urlopen")
    def test_reads_supported_status_with_size_limit(self, mocked_open: MagicMock) -> None:
        payload = json.dumps(
            {"firmware": "offline-1.0.0-beta.1", "meter_fresh": True, "rx_gpio": 3}
        ).encode()
        response = MagicMock()
        response.status = 200
        response.headers.get_content_type.return_value = "application/json"
        response.read.return_value = payload
        mocked_open.return_value.__enter__.return_value = response
        result = fetch_tracker_status("192.168.178.66")
        self.assertTrue(result["meter_fresh"])
        self.assertEqual(result["rx_gpio"], 3)
        requested = mocked_open.call_args.args[0]
        self.assertEqual(requested.full_url, "http://192.168.178.66/api/v1/status")

    @patch("installer.tracker_client.urlopen")
    def test_rejects_non_tracker_json(self, mocked_open: MagicMock) -> None:
        response = MagicMock()
        response.status = 200
        response.headers.get_content_type.return_value = "application/json"
        response.read.return_value = b'{"hello":"world"}'
        mocked_open.return_value.__enter__.return_value = response
        with self.assertRaises(TrackerClientError):
            fetch_tracker_status("192.168.1.20")

    @patch("installer.tracker_client.time.sleep", return_value=None)
    @patch("installer.tracker_client._admin_json_request")
    def test_gpio_scan_accepts_only_reported_crc_result(
        self, request: MagicMock, _sleep: MagicMock
    ) -> None:
        request.side_effect = [
            {"csrf_token": "a" * 64},
            {
                "active": True, "complete": False, "found": False,
                "tested": 0, "total": 44, "current_pin": 0,
                "current_baud": 9600,
            },
            {
                "active": False, "complete": True, "found": True,
                "tested": 13, "total": 44, "found_pin": 3,
                "found_baud": 9600,
            },
        ]
        progress = MagicMock()
        result = scan_tracker_gpio("192.168.178.66", "secret", progress)
        self.assertEqual(result, {"pin": 3, "baud": 9600})
        self.assertEqual(progress.call_count, 2)

    def test_gpio_scan_requires_admin_password(self) -> None:
        with self.assertRaisesRegex(TrackerClientError, "Admin-Passwort"):
            scan_tracker_gpio("192.168.178.66", "")

    @patch("installer.tracker_client._admin_json_request")
    def test_tx_scan_requires_repeated_optical_result(self, request: MagicMock) -> None:
        request.side_effect = [
            {"csrf_token": "a" * 64},
            {
                "complete": True, "found": True, "pin": 6,
                "inverted": False, "confidence": 96, "tested": 1,
                "active_transitions": 1, "idle_transitions": 82,
            },
        ]
        result = scan_tracker_tx("192.168.178.66", "secret", 3)
        self.assertEqual(result["pin"], 6)
        self.assertEqual(result["confidence"], 96)
        self.assertIn("rx=3", request.call_args_list[1].args[1])

    @patch("installer.tracker_client._admin_json_request")
    def test_tx_scan_does_not_confirm_without_loopback(self, request: MagicMock) -> None:
        request.side_effect = [
            {"csrf_token": "a" * 64},
            {"complete": True, "found": False, "tested": 10},
        ]
        with self.assertRaisesRegex(TrackerClientError, "Rückkanal"):
            scan_tracker_tx("192.168.178.66", "secret", 3)

    @patch("installer.tracker_client._admin_json_request")
    def test_output_pulse_requires_tracker_acknowledgement(
        self, request: MagicMock
    ) -> None:
        request.side_effect = [
            {"csrf_token": "a" * 64},
            {"accepted": True, "pin": 6, "duration_ms": 350},
        ]
        result = test_tracker_output("192.168.178.66", "secret", 6)
        self.assertEqual(result["pin"], 6)
        self.assertIn("pin=6", request.call_args_list[1].args[1])

    @patch("installer.tracker_client._admin_json_request")
    def test_output_uses_legacy_pulse_only_for_configured_candidate(
        self, request: MagicMock
    ) -> None:
        request.side_effect = [
            {"csrf_token": "a" * 64},
            TrackerClientError("alte Firmware"),
            {"accepted": True, "pulses": 1},
        ]
        result = test_tracker_output(
            "192.168.178.66", "secret", 6, allow_configured_fallback=True
        )
        self.assertEqual(result["mode"], "configured_tx_fallback")
        self.assertEqual(request.call_args_list[2].args[1].split("?")[0], "/ir/pulse")

    @patch("installer.tracker_client._admin_json_request")
    @patch("installer.tracker_client.urlopen")
    def test_wifi_update_posts_only_signed_irfw(
        self, mocked_open: MagicMock, admin_request: MagicMock
    ) -> None:
        admin_request.return_value = {"csrf_token": "a" * 64}
        response = MagicMock()
        response.status = 200
        response.read.return_value = b"ok"
        mocked_open.return_value.__enter__.return_value = response
        install_tracker_firmware(
            "192.168.178.66", "secret", "custom.irfw", b"x" * 2048
        )
        requested = mocked_open.call_args.args[0]
        self.assertEqual(requested.full_url, "http://192.168.178.66/system/update")
        self.assertEqual(requested.headers["X-csrf-token"], "a" * 64)
        self.assertIn(b'filename="custom.irfw"', requested.data)

    def test_wifi_update_rejects_raw_bin(self) -> None:
        with self.assertRaisesRegex(TrackerClientError, "irfw"):
            install_tracker_firmware(
                "192.168.178.66", "secret", "custom.bin", b"x" * 2048
            )


if __name__ == "__main__":
    unittest.main()
