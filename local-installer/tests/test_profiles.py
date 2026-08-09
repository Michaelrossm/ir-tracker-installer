from __future__ import annotations

import unittest
from pathlib import Path

from installer.models import DeviceInfo
from installer.profiles import ProfileStore, inspect_backup, sha256_file


ROOT = Path(__file__).resolve().parents[2]


class ProfileTests(unittest.TestCase):
    @unittest.skipUnless(
        (ROOT / "original bin" / "solakon-powertracker-original-full.bin").is_file(),
        "private original firmware backup is intentionally not published",
    )
    def test_known_local_original_matches_exact_profile(self) -> None:
        backup = ROOT / "original bin" / "solakon-powertracker-original-full.bin"
        fingerprints = inspect_backup(backup)
        result = ProfileStore(ROOT / "local-installer" / "profiles").match(
            DeviceInfo(
                port="TEST",
                chip="ESP32-C3 (revision v0.4)",
                mac="00:00:00:00:00:00",
                flash_size=4 * 1024 * 1024,
            ),
            fingerprints,
        )
        self.assertTrue(result.compatible)
        self.assertEqual(result.confidence, "exact-fingerprint")

    def test_release_artifacts_match_profile(self) -> None:
        profile = ProfileStore(ROOT / "local-installer" / "profiles").get(
            "solakon-ir-tracker-v1"
        )
        self.assertEqual(
            sha256_file(ROOT / profile.firmware), profile.firmware_sha256
        )
        self.assertEqual(
            sha256_file(ROOT / profile.partitions), profile.partitions_sha256
        )


if __name__ == "__main__":
    unittest.main()
