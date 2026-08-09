# Sicherer lokaler Installer / Safe local installer

## Deutsch

Der Installer wird als eigenständiges, quelloffenes nichtkommerzielles Projekt veröffentlicht. Windows und
Linux verwenden denselben erzwungenen Ablauf:

1. ESP über USB erkennen und Sicherheitsstatus prüfen.
2. Gesamten Flash lesen und bytegenau verifizieren.
3. Hardware nur über ein freigegebenes Fingerprint-Profil zulassen.
4. Geprüfte Firmware- und Partitionsartefakte schreiben.
5. Den IR-RX-Pin und die Baudrate durch ein echtes CRC-geprüftes SML-Telegramm ermitteln.
6. Mit dem verifizierten Komplettbackup auf die Original-Firmware zurückkehren.
7. Frühere Sicherungen nach einem Neustart katalogisieren, erneut prüfen und laden.
8. Einen bereits laufenden Custom-Tracker über seine private WLAN-IP auslesen.

Jede Sicherung kann zusätzlich als vollständige BIN und als JSON-Prüfbericht über
den Browser gespeichert werden. Beim erneuten Laden werden Geräteidentität,
Dateigröße, SHA-256 und Flash-Fingerprints kontrolliert.

Der Sicherungsordner lässt sich direkt aus der Oberfläche öffnen. Simulationsbackups
liegen nur in einem temporären Sitzungsordner und werden beim Beenden entfernt;
Sicherungen echter Geräte bleiben dauerhaft erhalten.
Während einer Vollsicherung bleiben Status und Protokoll erreichbar. Eine Liveanzeige
zeigt getrennt das Lesen des Flashs, die bytegenaue Verifikation sowie die lokale
Prüfsummen-/Manifesterstellung einschließlich Prozentwert und Laufzeit.

Als Firmwarequelle stehen die integrierte SHA-256-geprüfte Version, eine lokale
`.bin`- oder signierte `.irfw`-Datei und das neueste signierte `.irfw`-Paket aus den
GitHub-Releases zur Auswahl. Eine rohe lokale BIN verlangt zusätzlich die Bestätigung
`UNSIGNIERTE BIN`. Der GitHub-Download berücksichtigt auch als Pre-release markierte
Beta-Versionen und akzeptiert ausschließlich ein Asset namens
`ir-tracker-custom-*.irfw` mit gültiger Signatur.

Die Sicherheitsbestätigung vor dem Flashen ist ein bewusst anzuhakendes Kästchen;
bei einer unsignierten BIN erscheint ein zweites Risikokästchen. Der WLAN-Test liest
über `/api/v1/status` Leistung, Bezug, Einspeisung, L1–L3 (V/A/W), Empfangsqualität
und die konfigurierten RX/TX/LED-GPIOs. Ein frisches CRC-gültiges Telegramm bestätigt
den RX-Eingang. Die Suche testet GPIO 0–10 und gängige Baudraten flüchtig; Profilwerte
werden nie als Suchergebnis ausgegeben. Nach bestätigt erkanntem RX wird TX durch ein
optisches Testmuster automatisch gesucht und nur bei eindeutiger Rückkopplung übernommen.
Ein manueller Sichttest bleibt als Rückfall verfügbar; die Gehäuse-LED erfordert eine
sichtbare Bestätigung. Für den geschützten Suchlauf ist das Admin-Passwort erforderlich.
Zulässig sind ausschließlich direkt eingegebene private IPv4-Adressen.
Das optionale Admin-Passwort bleibt nur im RAM der laufenden Installer-Sitzung und
wird nicht protokolliert. USB-Trennen und -Verbinden wird ausschließlich im Simulator
angeboten.

### Fertige Programme starten

- Windows: `local-installer/dist/IR-Tracker-Installer.exe`
- Linux: `local-installer/dist-linux/IR-Tracker-Installer`

Die Oberfläche öffnet sich im Standardbrowser und ist ausschließlich über
`127.0.0.1` erreichbar. Für einen gefahrlosen Probelauf oben **Simulation starten**
wählen. Der virtuelle ESP startet mit **Solakon Original**, unterstützt die simulierte
BIN-Installation, USB-Trennen und -Verbinden sowie die Wiederherstellung per Knopfdruck.
Seine Setup-IP `192.168.4.1` wird innerhalb des Simulators beantwortet, ohne einen
echten Netzwerkadapter anzulegen. Der Ablauf prüft zuerst diese WLAN-Verbindung und
die simulierten Zählerwerte. RX-, TX- und LED-GPIO sowie Baudrate lassen sich vorgeben;
die danach freigegebene Suche prüft die RX-/Baud-Kombination nacheinander. TX und LED
werden auch in der Simulation separat über den Ausgangstest bestätigt.

Die Custom-BIN und ihre Partitionstabelle sind eingebettet. Eine originale
Hersteller-BIN wird niemals in das Programm gepackt. Der Simulator verwendet eine
lokal vorhandene private Sicherung oder ersatzweise einen synthetischen 4-MiB-Flash.

Die echte Erstinstallation ist ausschließlich über USB vorgesehen. Unbekannte
Hardware, abweichende Original-Firmware, Secure Boot, Flash-Verschlüsselung oder
Secure Download Mode sperren den Schreibvorgang. Der Simulator und die Paketdateien
sind automatisiert geprüft; ein Test mit einem realen weiteren Gerät steht noch aus.
Klassische ESP32/ESP-WROOM-Module werden einschließlich ihrer eFuses erkannt und
können zunächst vollständig gesichert werden. Die derzeit veröffentlichte
ESP32-C3-Firmware wird auf dieser abweichenden Architektur ausdrücklich nicht
freigegeben oder geschrieben.

### Aus dem Quellstand starten oder bauen

```text
python local-installer/start.py --virtual
powershell -ExecutionPolicy Bypass -File local-installer/build-windows.ps1
sh local-installer/build-linux.sh
```

Backups einer gepackten Windows-Ausgabe liegen unter
`%LOCALAPPDATA%/IRTrackerInstaller/backups`; unter Linux im XDG-Datenverzeichnis
beziehungsweise unter `~/.local/share/IRTrackerInstaller/backups`.

## English

The installer is published as a standalone source-available noncommercial project. Windows and Linux
enforce the same workflow:

1. Detect the ESP over USB and inspect its security state.
2. Read the complete flash and verify it byte for byte.
3. Allow hardware only through an approved fingerprint profile.
4. Write checksum-approved firmware and partition artifacts.
5. Detect the IR RX pin and baud rate through a real CRC-verified SML telegram.
6. Restore the original firmware from the verified full-flash backup.
7. Catalogue, revalidate, and load earlier backups after an application restart.
8. Read an already running custom tracker through its private Wi-Fi address.

Each backup can also be saved through the browser as a complete BIN and a JSON
verification report. Reloading checks device identity, file size, SHA-256, and flash
fingerprints.

The backup folder can be opened directly from the UI. Simulation backups use a
temporary session directory and are removed when the installer exits; physical-device
backups remain persistent.
During a full backup, status and logs remain available. A live indicator separately
shows flash reading, byte-for-byte verification, and local checksum/manifest creation,
including percentage and elapsed time.

Firmware selection supports the bundled checksum-approved image, a local `.bin` or
signed `.irfw` file, and the latest signed `.irfw` asset from GitHub Releases. Raw
local BIN files require the additional confirmation `UNSIGNIERTE BIN`. GitHub
selection includes beta versions marked as pre-releases and accepts only a correctly
signed asset named `ir-tracker-custom-*.irfw`.

The pre-flash safety confirmation is an explicit checkbox; an unsigned BIN displays
a second risk checkbox. The Wi-Fi check reads power, import, export, L1–L3 (V/A/W),
reception health, and the configured RX/TX/LED GPIOs through `/api/v1/status`. A fresh,
CRC-valid telegram verifies the RX input. The volatile scan tests GPIO 0–10 and common
baud rates; profile defaults are never presented as scan results. After RX verification,
TX is scanned automatically with an optical test pattern and accepted only after
unambiguous loopback detection. A manual visual fallback remains available; the case
LED still needs visible confirmation. The protected scan requires the admin password.
Only literal private IPv4 addresses are
accepted. The optional admin password remains in RAM for the current installer session
and is never logged. USB disconnect/reconnect controls are available in simulation only.

### Run the packaged applications

- Windows: `local-installer/dist/IR-Tracker-Installer.exe`
- Linux: `local-installer/dist-linux/IR-Tracker-Installer`

The UI opens in the default browser and only listens on `127.0.0.1`. Select
**Simulation starten** for a risk-free dry run. The virtual ESP initially displays
**Solakon Original** and supports simulated BIN installation, USB disconnect and
reconnect, and one-button restoration.
Its setup IP `192.168.4.1` is answered inside the simulator without creating a real
network adapter. The workflow first checks this Wi-Fi connection and simulated meter
values. RX, TX, and LED GPIOs plus baud rate can be configured; detection is enabled
afterwards and sequentially tests the RX/baud combination. TX and LED are confirmed
separately through the output test in simulation as well.

The custom BIN and partition table are bundled. An original manufacturer BIN is
never bundled. The simulator uses a private local backup when available, otherwise a
synthetic 4 MiB flash image.

Real first-time installation is USB-only. Unknown hardware, a different original
firmware fingerprint, Secure Boot, flash encryption, or Secure Download Mode blocks
all writes. Automated source and packaged-simulator tests pass; testing with another
physical device is still outstanding.
Classic ESP32/ESP-WROOM modules are detected including their eFuses and can first be
backed up in full. The currently released ESP32-C3 firmware is explicitly not approved
or written to this different architecture.

### Run or build from source

```text
python local-installer/start.py --virtual
powershell -ExecutionPolicy Bypass -File local-installer/build-windows.ps1
sh local-installer/build-linux.sh
```

Packaged backups are stored under `%LOCALAPPDATA%/IRTrackerInstaller/backups` on
Windows and in the XDG data directory or
`~/.local/share/IRTrackerInstaller/backups` on Linux.
