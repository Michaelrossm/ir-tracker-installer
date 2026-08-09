# IR Tracker Installer 1.0.1 Beta

Safe, guided Windows and Linux installer for compatible ESP32-C3 IR smart-meter
trackers. Developed by Michael Roßmann. The interface and documentation are available
in German and English.

Sicherer, geführter Windows- und Linux-Installer für kompatible ESP32-C3-IR-
Stromzähler-Tracker. Entwickelt von Michael Roßmann. Oberfläche und Dokumentation
sind auf Deutsch und Englisch verfügbar.

> **Beta / important:** Only hardware with a verified fingerprint profile can be
> written. Unknown devices can be inspected and backed up, but are never flashed.
>
> **Beta / wichtig:** Nur Hardware mit verifiziertem Fingerprint-Profil darf
> beschrieben werden. Unbekannte Geräte können geprüft und gesichert, aber niemals
> geflasht werden.

## Download / Herunterladen

Open the current [GitHub beta release](https://github.com/Michaelrossm/ir-tracker-installer/releases/tag/v1.0.1-beta.1):

- Windows: `IR-Tracker-Installer-Windows-v1.0.1-beta.1.exe`
- Linux x86_64: `IR-Tracker-Installer-Linux-v1.0.1-beta.1`
- Verify the matching SHA-256 value in `SHA256SUMS.txt`.

No installation is required. Start the program; its browser UI listens only on
`127.0.0.1`. Select **Simulation starten / Start simulation** for a risk-free test.

Keine Installation erforderlich. Programm starten; die Browseroberfläche lauscht nur
auf `127.0.0.1`. Für einen gefahrlosen Test **Simulation starten / Start simulation**
wählen.

## Safety workflow / Sicherheitsablauf

1. Detect the chip and security state / Chip und Sicherheitsstatus erkennen.
2. Read and byte-verify the complete 4 MiB flash / vollständigen 4-MiB-Flash lesen und prüfen.
3. Match an approved hardware fingerprint / freigegebenen Hardware-Fingerprint abgleichen.
4. Verify the bundled or selected firmware / Firmwareartefakt prüfen.
5. Recheck device identity before writing / Geräteidentität vor dem Schreiben erneut prüfen.
6. Detect RX by CRC-valid SML and TX by optical loopback / RX über CRC-SML und TX über optische Rückkopplung erkennen.

The original manufacturer firmware is **never included**. Restoration is possible only
from the user's own verified full-flash backup. Passwords remain in RAM and are not
logged. Wi-Fi updates write only the signed custom application; partitions, settings,
Wi-Fi credentials, and history remain unchanged.

Originale Hersteller-Firmware wird **niemals mitgeliefert**. Eine Wiederherstellung ist
nur aus der eigenen verifizierten Vollsicherung möglich. Passwörter bleiben im RAM und
werden nicht protokolliert. WLAN-Updates schreiben nur die signierte Custom-App;
Partitionen, Einstellungen, WLAN-Daten und Historie bleiben unverändert.

## Build and tests / Bauen und testen

```powershell
$env:PYTHONPATH = (Resolve-Path local-installer).Path
python -m unittest discover -s local-installer/tests -p "test_*.py"
powershell -ExecutionPolicy Bypass -File local-installer/build-windows.ps1
```

```sh
PYTHONPATH=local-installer python3 -m unittest discover -s local-installer/tests -p 'test_*.py'
sh local-installer/build-linux.sh
```

Architecture details: [local-installer/DESIGN.md](local-installer/DESIGN.md).
Detailed usage: [local-installer/README.md](local-installer/README.md).

## License and independence / Lizenz und Unabhängigkeit

Copyright © 2026 Michael Roßmann. Licensed under PolyForm Noncommercial 1.0.0; commercial
use is not permitted by this license. See the [license](LICENSE.md), [authorship notice](AUTHORS.md),
[rights review](RIGHTS_REVIEW.md), and [trademark notice](TRADEMARKS.md). This independent
community project is not affiliated with, endorsed by, or supported by Solakon or any
meter manufacturer.

Copyright © 2026 Michael Roßmann. Lizenziert unter PolyForm Noncommercial 1.0.0;
gewerbliche Nutzung ist durch diese Lizenz nicht erlaubt. Siehe [Lizenz](LICENSE.md),
[Urheberhinweis](AUTHORS.md), [Rechteprüfung](RIGHTS_REVIEW.md) und
[Markenhinweis](TRADEMARKS.md). Dieses unabhängige Community-Projekt ist weder mit
Solakon noch mit einem Zählerhersteller verbunden oder von diesen unterstützt.
