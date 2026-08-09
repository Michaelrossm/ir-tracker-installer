import os
import unittest
from unittest.mock import patch

from installer.self_update import INSTALLER_VERSION, _asset_prefix, _version_number


class SelfUpdateTests(unittest.TestCase):
    def test_beta_versions_are_ordered_without_downgrade(self):
        self.assertGreater(_version_number("v1.0.1-beta.2"), _version_number(INSTALLER_VERSION))
        self.assertLess(_version_number("v1.0.0"), _version_number(INSTALLER_VERSION))

    def test_platform_asset_name_is_explicit(self):
        expected = "IR-Tracker-Installer-Windows-" if os.name == "nt" else "IR-Tracker-Installer-Linux-"
        self.assertEqual(_asset_prefix(), expected)


if __name__ == "__main__":
    unittest.main()
