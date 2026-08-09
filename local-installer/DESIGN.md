# Architektur und Sicherheitsablauf / Architecture and security workflow

## Deutsch

Die Reihenfolge ist unveränderlich:

`Auswahl → Inspektion → Vollbackup → Byteprüfung → Profilabgleich → erneute Geräteprüfung → Flash → WLAN-/GPIO-Prüfung`

Der Zustandsautomat und ein Prozess-Lock verhindern Überspringen und parallele
Schreibvorgänge. Vor jedem USB-Flash werden Identität, Sicherheitseinstellungen,
Firmwareartefakt und vollständiges Backup erneut geprüft. Unbekannte Fingerprints,
Secure Boot, Flash-Verschlüsselung und Secure Download Mode sperren das Schreiben.

Die Oberfläche lauscht ausschließlich auf `127.0.0.1`. Schreibende Anfragen brauchen
ein zufälliges Sitzungstoken. Antworten verbieten Framing, Referrer, Browser-Hardware-
Berechtigungen und Zwischenspeicherung. Passwörter verbleiben im RAM und erscheinen
nicht im Protokoll. WLAN akzeptiert nur literale private IPv4-Adressen.

Das WLAN-Update schreibt ausschließlich die signierte Custom-App in den OTA-Slot.
Bootloader, Partitionstabelle, WLAN-Daten, Einstellungen und Historie bleiben erhalten.
RX gilt nur nach einem neuen vollständigen CRC-gültigen SML-Telegramm mit plausiblen
OBIS-Werten als erkannt. TX gilt nur nach eindeutiger optischer Rückkopplung als
automatisch bestätigt.

## English

The order is immutable:

`selection → inspection → full backup → byte verification → profile match → device recheck → flash → Wi-Fi/GPIO verification`

The state machine and a process lock prevent skipped steps and concurrent writes.
Before every USB flash, identity, security settings, the firmware artifact, and the
complete backup are checked again. Unknown fingerprints, Secure Boot, flash encryption,
and Secure Download Mode block all writes.

The UI listens only on `127.0.0.1`. Mutating requests require a random session token.
Responses disable framing, referrers, browser hardware permissions, and caching.
Passwords stay in RAM and are never logged. Wi-Fi accepts literal private IPv4
addresses only.

Wi-Fi update writes only the signed custom application to its OTA slot. Bootloader,
partition table, Wi-Fi credentials, settings, and history are preserved. RX is accepted
only after a new complete CRC-valid SML telegram with plausible OBIS values. TX is
automatically confirmed only after unambiguous optical loopback detection.
