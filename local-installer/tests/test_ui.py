from __future__ import annotations

import shutil
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.scripts: list[str] = []
        self._script: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if tag == "script" and "src" not in attributes:
            self._script = []

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._script is not None:
            self.scripts.append("".join(self._script))
            self._script = None


class UiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.html = (ROOT / "local-installer" / "ui" / "index.html").read_text(
            encoding="utf-8"
        )
        self.parser = Collector()
        self.parser.feed(self.html)

    def test_required_controls_exist_once(self) -> None:
        self.assertEqual(len(self.parser.ids), len(set(self.parser.ids)))
        for control in (
            "ports",
            "realMode",
            "virtualMode",
            "usbDisconnect",
            "usbConnect",
            "virtualIp",
            "virtualRx",
            "virtualTx",
            "virtualLed",
            "virtualBaud",
            "virtualConfig",
            "restoreOriginal",
            "shutdown",
            "select",
            "inspect",
            "backup",
            "operationPanel",
            "operationBar",
            "operationPercent",
            "openBackupFolder",
            "firmwareFile",
            "useLocalFirmware",
            "useGithubFirmware",
            "backupConfirmed",
            "unsignedConfirmed",
            "flash",
            "scan",
            "gpioResult",
            "nextPin",
            "outputTestHint",
            "gpioScanPanel",
            "gpioScanBar",
            "gpioScanPercent",
            "gpioScanCurrent",
            "gpioScanCount",
            "testPin",
            "confirmPin",
            "trackerIp",
            "trackerPassword",
            "trackerConnect",
            "trackerDisconnect",
            "meterValues",
            "phaseValues",
            "log",
        ):
            self.assertIn(control, self.parser.ids)
        self.assertNotIn("flashConfirm", self.parser.ids)
        self.assertEqual(self.html.count("__INSTALLER_TOKEN__"), 1)

    @unittest.skipUnless(shutil.which("node"), "Node.js not installed")
    def test_inline_javascript_parses(self) -> None:
        script = "\n".join(self.parser.scripts).replace(
            "__INSTALLER_TOKEN__", "test-token"
        )
        result = subprocess.run(
            [
                "node",
                "-e",
                "new Function(require('fs').readFileSync(0, 'utf8'))",
            ],
            input=script,
            text=True,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
