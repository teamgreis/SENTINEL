# SENTINEL 2.2 Beta — Anleitung

**© Felix Greis (Hacker-Name: Elian)** · Version 2.2 Beta · „Protect. Detect. Understand."

## Was ist neu in 2.2

- **Multi-User mit Rollen**: Admins verwalten, Nutzer prüfen. Der letzte Admin ist geschützt.
- **Windows-Hello-Anmeldung**: PIN, Fingerabdruck oder Gesicht öffnen die Sperre.
- **Zwei Backup-Codes** beim Einrichten — die Rettung bei vergessenem Passwort.
- **Windows-Konten-Import**: alle lokalen Windows-Nutzer werden übernommen.
- **Sperre bei jedem Start**: erst Anmeldung, dann App.

## Erster Start

1. **Onboarding**: Anzeigename + Passwort (min. 8 Zeichen). Das erste Konto ist **Administrator**.
2. **Backup-Codes**: zwei Codes werden angezeigt. **Ausdrucken oder notieren!** Danach sind sie nur noch als Hash gespeichert. Jeder Code gilt **einmal**.
3. Danach öffnet sich die **Sperre** — Anmeldung mit Passwort oder Windows Hello.

## Anmelden (jeder Start)

- **Passwort** + optional **Windows Hello** (PIN/Biometrie).
- **Backup-Code**: öffnet den Dialog „Passwort zurücksetzen" — der Code wird dabei verbraucht.
- 5 Fehlversuche = 15 Minuten Sperre.

## Nutzer verwalten (nur Admins)

Seite **Nutzer & Rollen**:
- **+ Nutzer hinzufügen**: Name, Passwort, Rolle (Admin/Nutzer).
- **Windows-Konten importieren**: übernimmt die lokalen Windows-Benutzer (Systemkonten werden gefiltert). Für alle wird ein Sentinel-Passwort vergeben.
- **Rolle** wechseln, **Passwort** zurücksetzen (Admin-Aktion), **Entfernen** (mit Admin-Passwort bestätigt).

## Bedrohungs-Datenbanken

Ohne Key sofort nutzbar: **ThreatFox, MalwareBazaar, URLhaus**.
Mit kostenlosem Key (Einstellungen): **VirusTotal, Google Safe Browsing, AlienVault OTX**.

## Ehrliche Grenzen

- **„PC sperren wenn deinstalliert"** wurde bewusst NICHT eingebaut: ein Bug oder eine korrupte Datei würde dich dauerhaft aussperren. Das ist Ransomware-Verhalten, kein Schutz.
- **Windows-Reset überleben** ebenfalls nicht: „Diesen PC zurücksetzen" ist die Notfall-Rettung und muss funktionieren.
- **Login vor der Windows-Anmeldung** bräuchte eine Credential Provider (Treiber-Ebene + Microsoft-Signatur). SENTINEL startet mit Windows, aber nach der Windows-Anmeldung.
- **„Unhackbar"** gibt es nicht. Was SENTINEL hat: PBKDF2-SHA512 (210k), zeitkonstanten Vergleich, Sperrlogik, Backup-Code-Hashes, Rollenschutz für den letzten Admin.

## Signierung

Siehe `SIGNIERUNG.md` — Smart App Control blockiert unsignierte Builds.
