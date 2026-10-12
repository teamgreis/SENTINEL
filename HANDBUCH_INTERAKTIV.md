# SENTINEL — Interaktives Handbuch

**© Felix Greis (Alias: Elian)** · Version 2.5 Beta · [ Zurück zum README ](#)

> **Für wen ist das?** Du hast SENTINEL noch nie benutzt — oder du weißt nicht,
> was ein bestimmter Knopf tut. Dieses Handbuch führt dich Schritt für Schritt
> durch alles. Jedes Kapitel steht für sich; du musst nicht der Reihe nach lesen.

---

## Schnellnavigation

| Ich will… | Kapitel |
|---|---|
| …loslegen | [Erste Schritte](#1-erste-schritte) |
| …mich anmelden | [Anmelden](#2-anmelden) |
| …den Score verstehen | [Die Übersicht lesen](#3-die-übersicht-lesen) |
| …eine Prüfung starten | [Eine Prüfung starten](#4-eine-prüfung-starten) |
| …einen Link prüfen | [Links und Dateien prüfen](#5-links-und-dateien-prüfen) |
| …Nutzer verwalten | [Nutzer und Rollen](#6-nutzer-und-rollen) |
| …das Design wechseln | [Das Design wechseln](#7-das-design-wechseln) |
| …Info und Lizenz finden | [Info-Dialog und Handbuch](#8-info-dialog-und-handbuch) |
| …mein Passwort vergessen | [Passwort vergessen](#9-passwort-vergessen) |
| …wissen, was SENTINEL *nicht* kann | [Grenzen](#10-grenzen-ehrliche-antworten) |

---

## 1. Erste Schritte

**Dauer: ca. 3 Minuten**

### Schritt 1 — Starten
Entpacke das Archiv und starte `SENTINEL-win-x64\Sentinel.exe`.

Beim ersten Start erscheint automatisch die **Einrichtung**. Das ist gewollt:
SENTINEL kennt noch keinen Nutzer und soll auch keinen anlegen, den du nicht
selbst bestimmt hast.

### Schritt 2 — Admin anlegen
- **Name:** Dein Anzeigename.
- **Passwort:** Mindestens **8 Zeichen**, besser **12+**. Die Stärkeanzeige
  unter dem Feld zeigt dir live, wie gut das Passwort ist.

> **Warum ein Passwort, wenn Windows schon eins hat?**
> Weil SENTINEL eigenständig sperrt. Jeder, der den PC startet, kommt zuerst
> zur SENTINEL-Sperre — auch auf einem Windows-Konto ohne Passwort.

### Schritt 3 — Backup-Codes
Nach der Passwort-Vergabe zeigt SENTINEL **zwei Backup-Codes**.

```
Beispiel:
SNT-7K4M-9X2P
SNT-3B8N-6W1Q
```

**Schreibe sie jetzt auf.** Sie werden **nur dieses eine Mal** angezeigt.
SENTINEL speichert sie nicht im Klartext — nur als sichere Hashes. Wer den
Code verliert und das Passwort vergisst, kommt nicht mehr herein.

### Schritt 4 — Fertig
Klicke „Einrichtung abschließen". Beim nächsten Start erscheint die Sperre.

> **Tipp:** Rechtsklick auf `Sentinel.exe` → **„Als Administrator ausführen"**.
> Damit siehst du die meisten Prüfergebnisse. Ohne Admin-Rechte melden einzelne
> Prüfungen ehrlich „unklar" — sie lügen nicht, sie wissen es nur nicht.

---

## 2. Anmelden

Beim **jeden** Start erscheint zuerst die Sperre. Drei Wege:

### Weg 1 — Passwort
1. Wähle oben links deinen Nutzer.
2. Tippe das Passwort.
3. Enter.

### Weg 2 — Windows Hello
1. Wähle deinen Nutzer.
2. Klicke „Mit Windows Hello anmelden".
3. Windows fragt nach PIN, Gesicht oder Fingerabdruck — der gewohnte Systemdialog.

> **Wichtig:** Windows Hello funktioniert nur für den Nutzer, der dem
> **angemeldeten Windows-Konto** entspricht. Das ist Absicht: Hello beweist
> „jemand sitzt an diesem Windows-Konto" — nicht „diese bestimmte Person".
> Wer sich als anderer SENTINEL-Nutzer anmelden will, nimmt das Passwort.

### Weg 3 — Backup-Code
Wenn das Passwort weg ist. Siehe [Kapitel 9](#9-passwort-vergessen).

### Schutz gegen Durchprobieren
Nach **5 falschen Versuchen** ist das Konto für **15 Minuten** gesperrt.
Das ist keine Strafe, sondern Schutz: Ein Angreifer kann nicht tausende
Kombinationen pro Minute testen.

---

## 3. Die Übersicht lesen

Die Übersicht ist das Herzstück. So liest du sie:

### Der Score-Ring
Die große Zahl in der Mitte, **0 bis 100**:

| Note | Score | Bedeutung |
|---|---|---|
| 🟢 Gut | 70–100 | Die meisten Schutzmaßnahmen sind aktiv. |
| 🟡 Verbesserungsbedarf | 40–69 | Es gibt Lücken, aber nichts Dramatisches. |
| 🔴 Kritisch | unter 40 — **oder eine einzelne schwere Warnung** | Mindestens ein wichtiger Schutz fehlt. |

> **Warum zählt eine schwere Warnung sofort als kritisch?**
> Weil ein Score von 85 mit abgeschaltetem Echtzeitschutz eine Falle ist.
> SENTINEL betont das Schwere stärker als die Menge der Bestandenen.

### Die Prüfungsliste
Darunter stehen alle Ergebnisse, gruppiert:

- **Bestanden** — alles in Ordnung.
- **Hinweis** — nicht perfekt, aber unkritisch.
- **Problem** — hier solltest du handeln.
- **Unklar** — SENTINEL konnte es nicht prüfen.

> **„Unklar" ist keine Schwäche.** Es bedeutet: die Abfrage scheiterte, meist
> aus Rechtegründen. Als Administrator starten löst das in den meisten Fällen.

### Jeder Befund hat drei Teile
1. **Was** — der Befund in einem Satz.
2. **Warum zählt das?** — die Erklärung.
3. **Nächste Schritte** — konkrete Handlungsanweisungen.

Lies die Erklärung. Sie sagt dir, ob der Befund für **dich** relevant ist —
nicht jeder Hinweis ist für jeden Nutzer gleich wichtig.

---

## 4. Eine Prüfung starten

### Vorher: Tiefe wählen
In den **Einstellungen → Prüfungen** wählst du die Tiefe:

- **Schnell** — nur die wichtigsten Prüfungen, wenige Sekunden.
- **Standard** — der ausgewogene Modus.
- **Tiefenprüfung** — alle 48 Checks, dauert länger.

### Starten
„Prüfung starten" auf der Übersicht. Während der Prüfung:
- Jede Gruppe zeigt ihren Fortschritt.
- „Abbrechen" ist jederzeit möglich — was schon geprüft ist, bleibt sichtbar.

### Export
„Export" speichert das Ergebnis. Zwei Formate:
- **HTML** — formatiert, zum Ausdrucken und Weitergeben.
- **Text** — schlicht, für Notizen.

---

## 5. Links und Dateien prüfen

### LinkShield — ist diese Web-Adresse gefährlich?
1. Seite „LinkShield" öffnen.
2. Adresse einfügen (die ganze URL, mit `https://`).
3. „Prüfen" klicken.

SENTINEL fragt mehrere Bedrohungsdatenbanken ab und zeigt ein
Gesamturteil mit der Einschätzung jeder einzelnen Datenbank.

> **Vor der ersten Online-Prüfung** erscheint ein Einwilligungsdialog. Er sagt
> genau, was übertragen wird: **nur die Adresse**. Keine Dateien, keine
> persönlichen Daten. Ohne Einwilligung bleibt die Prüfung lokal.

### FileShield — ist diese Datei bekannt als Schadsoftware?
1. Seite „FileShield" öffnen.
2. Datei auswählen.
3. SENTINEL berechnet den **SHA-256-Hash** und prüft ihn.

> **Was verlässt deinen PC?** Nur der 64-stellige Hash. Der Dateiinhalt und
> der Dateiname bleiben auf deinem Rechner. Ein Hash ist eine Einweg-Quersumme:
> Man kann daraus die Datei nicht zurückrechnen.

### Einwilligung zurücknehmen
Einstellungen → Online-Prüfungen → ausschalten. Jederzeit widerrufbar.

---

## 6. Nutzer und Rollen

> **Nur für Admins.** Normale Nutzer sehen diese Seite nicht.

### Nutzer hinzufügen
1. „Nutzer hinzufügen".
2. Name, Passwort, Rolle (Admin oder Nutzer).
3. Bestätigen. Die Passwort-Stärke wird live angezeigt.

### Windows-Konten importieren
„Windows-Konten importieren" zeigt alle lokalen Windows-Benutzer.
Ausgewählte werden als SENTINEL-Nutzer übernommen (Rolle: Nutzer).
Systemkonten sind automatisch ausgefiltert.

### Rollen
- **Admin** — sieht alle Seiten, darf Nutzer verwalten.
- **Nutzer** — sieht Prüfungen, aber keine Nutzerverwaltung.

### Der letzte Admin ist geschützt
SENTINEL verhindert, dass du den **letzten verbliebenen Admin** löschst oder
zurückstuft. Das ist kein Bug: Sonst könnte sich jemand versehentlich
vollständig aus dem System aussperren.

### Passwort zurücksetzen
Admins können das Passwort jedes Nutzers zurücksetzen — müssen dafür aber
**ihr eigenes** Passwort eingeben. Ein Admin kann sich also nicht selbst
oder andere ohne Wissen umgehen.

---

## 7. Das Design wechseln

**Einstellungen → Erscheinungsbild → Design.**

Fünf Designs stehen bereit:

| Design | Beschreibung |
|---|---|
| **Sentinel Dark** | Das Standard-Design: dunkles Violett mit Cyan-Akzenten. |
| **Midnight** | Tiefes Nachtblau — ruhiger für die Augen am Abend. |
| **DeepSpace** | Reines Schwarz mit Neon-Grün — Terminal-Optik. |
| **Solarized** | Warme Sepia-Töne auf Dunkelbraun. |
| **Mono** | Komplett farbfrei, Schwarz auf Weiß. Maximale Lesbarkeit, gedacht für Farbsehschwäche. |

Die Wahl **wirkt sofort** und wird gespeichert. Nach dem Neustart ist sie
wieder da.

> **Mono** ist nicht nur Deko: Ohne Farbe bleibt der Score-Ring über
> **Form und Zahl** unterscheidbar, nicht nur über Rot/Gelb/Grün. Das hilft
> bei Farbsehschwäche — und beim Drucken auf Schwarzweiß.

---

## 8. Info-Dialog und Handbuch

In den **Einstellungen** stehen zwei Buttons rechts oben:

### ⓘ Info
Öffnet ein Fenster mit drei Karteikarten:
- **Über** — Was SENTINEL ist, das Konzept, und die ehrlichen Grenzen.
- **Versionen** — das vollständige Änderungsprotokoll, neueste zuerst.
- **Lizenz** — der komplette MIT-Lizenztext.

### 📖 Handbuch
Öffnet dieses Handbuch **im Programm**. Du musst also nicht online gehen,
um nachzulesen, was ein Knopf tut.

---

## 9. Passwort vergessen

1. Auf der Sperre den **Backup-Code**-Weg wählen.
2. Einen der beiden Codes eingeben.
3. Ein neues Passwort festlegen.

Der Code ist danach **verbraucht** — er funktioniert nur einmal.

> **Beide Codes weg?** Dann muss ein anderer **Admin** dir ein neues Passwort
> setzen (Seite „Nutzer & Rollen"). Wenn du der einzige Admin bist und beide
> Codes weg sind, bleibt nur: Die Datei `users.json` im Datenordner löschen.
> SENTINEL startet dann neu mit der Einrichtung. **Das kostet alle Nutzer
> und Einstellungen** — deshalb die Codes aufschreiben.

---

## 10. Grenzen — ehrliche Antworten

SENTINEL sagt dir, was es **nicht** kann. Das ist wichtig, damit du dich
nicht auf etwas verlässt, das nicht hält.

### „Ist das ein Ersatz für mein Antivirenprogramm?"
**Nein.** Lass Windows Defender (oder dein Antivirenprogramm) aktiviert.
SENTINEL prüft, ob Defender *an* ist — es ersetzt ihn nicht.

### „Findet das alles?"
**Nein.** SENTINEL findet, was in Datenbanken gemeldet ist und was sich
lokal prüfen lässt. Eine völlig neue, unbekannte Bedrohung erkennt kein
Werkzeug — auch kein teures.

### „Kann ich mich zu 100 % sicher fühlen?"
**Nein, und das sagt SENTINEL bewusst.** Ein hoher Score bedeutet: Die
wichtigsten Schutzmaßnahmen sind aktiv. Er ist kein Beweis für absolute
Sicherheit. Ein physischer Angreifer an deinem PC überwindet jedes Software-Werkzeug.

### „Warum sperrt SENTINEL meinen PC nicht, wenn ich es deinstalliere?"
Weil genau das das Muster von **Ransomware** ist: Software, die den PC
sperrt und dabei das Löschen verhindert. SENTINEL ist ein Werkzeug für dich,
keine Falle. Wenn du es deinstallieren willst, gehört das dir — nicht dem
Programm. Ein Sicherheitstool, das du nicht loswirst, ist kein Sicherheitstool.

---

## Wo finde ich was? — Verzeichnis

| Was | Wo |
|---|---|
| Sicherheits-Score | Übersicht (Startseite) |
| Prüfung starten | Übersicht → „Prüfung starten" |
| Link prüfen | Seitenleiste → LinkShield |
| Datei prüfen | Seitenleiste → FileShield |
| Verlauf | Seitenleiste → Verlauf |
| Baseline | Seitenleiste → Baseline |
| Integrität | Seitenleiste → Integrität |
| Nutzer & Rollen | Seitenleiste (nur Admins) |
| Einstellungen | Seitenleiste → Einstellungen |
| Design, Info, Handbuch | Einstellungen → oben rechts |
| Lizenz | Einstellungen → ⓘ Info → Karteikarte „Lizenz" |

---

## Fehler? So meldest du sie

Öffne auf GitHub ein **Issue**:
https://github.com/teamgreis/SENTINEL/issues

Nenne dabei:
1. Was du getan hast.
2. Was passiert ist.
3. Was du erwartet hättest.

Den vollständigen Quellcode und die Test-Suite findest du im Repository:
https://github.com/teamgreis/SENTINEL

---

*SENTINEL 2.5 Beta · © Felix Greis (Alias: Elian) · Lizenz: MIT · Protect. Detect. Understand.*
