# Sicherheit / Security

## Deutsch

Sicherheitsprobleme bitte nicht öffentlich mit Zugangsdaten oder Gerätesicherungen
melden. Eine private GitHub-Sicherheitsmeldung ist bevorzugt. Niemals originale
Hersteller-BINs, vollständige Gerätesicherungen, WLAN-Passwörter oder private
Signierschlüssel anhängen.

Der Installer bindet nur an `127.0.0.1`, verlangt für schreibende HTTP-Aufrufe ein
zufälliges Sitzungstoken und akzeptiert beim WLAN-Test ausschließlich literale private
IPv4-Adressen. Trotzdem sollte er nur aus dem offiziellen Release in einem
vertrauenswürdigen lokalen Netz ausgeführt werden.

## English

Do not disclose credentials or device backups in a public report. Prefer a private
GitHub security advisory. Never attach original manufacturer BIN files, complete device
backups, Wi-Fi passwords, or private signing keys.

The installer binds only to `127.0.0.1`, requires a random session token for mutating
HTTP calls, and accepts only literal private IPv4 addresses for Wi-Fi checks. Run only
an official release in a trusted local network.
