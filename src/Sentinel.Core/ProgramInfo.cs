namespace Sentinel.Core;

/// <summary>
/// Statische Programm-Informationen für den Info-Dialog ('I"-Button in den
/// Einstellungen): Lizenz, Beschreibung, Konzept, Änderungsprotokoll.
/// </summary>
public static class ProgramInfo
{
    /// <summary>Was SENTINEL ist — ein Absatz, ehrlich formuliert.</summary>
    public const string Description =
        "SENTINEL ist ein lokales Analysewerkzeug für die Sicherheit deines Windows-PCs. " +
        "Es prüft über 40 Einzelaspekte — von der Firewall über die Festplattenverschlüsselung " +
        "bis zu offenen Server-Ports —, erklärt jeden Befund in verständlicher Sprache und " +
        "schlägt konkrete nächste Schritte vor. " +
        "SENTINEL ändert nichts an deinem System: jede Prüfung ist rein lesend. " +
        "Es ist kein Ersatz für ein Antivirenprogramm, sondern eine zweite, unabhängige Meinung.";

    /// <summary>Das Konzept in Stichpunkten (im Info-Dialog aufgeführt).</summary>
    public static readonly string[] Concept =
    {
        "Read-only zuerst: SENTINEL liest Registry, WMI und PowerShell-Abfragen, ändert aber nichts.",
        "Lokal vor Cloud: Alle Prüfungen laufen auf dem eigenen PC. Keine Telemetrie, kein Tracking.",
        "Datenminimierung: Online-Prüfungen senden nur die geprüfte Adresse oder den SHA-256-Hash einer Datei — niemals Dateiinhalte, Dateinamen oder persönliche Daten.",
        "Einwilligung als Schalter: Online-Datenbanken werden nur nach ausdrücklicher Zustimmung kontaktiert. Der Schalter ist jederzeit umlegbar.",
        "Erklären statt erschrecken: Jeder Befund kommt mit einer Erklärung, warum er zählt, und mit Grenzen der Prüfung.",
        "Konservative Bewertung: Unklare Ergebnisse bleiben aus der Wertung. Eine Warnung zählt halb. Eine einzelne schwere Warnung genügt für die Note 'Kritisch'.",
        "Mehrstufige Erkennung: Wenn eine Abfrage scheitert, wird die nächste versucht (z. B. Defender-Dienst → WMI → Registry). Scheitern alle, sagt SENTINEL ehrlich 'unklar' statt zu raten.",
        "Keine Hintertüren: Kein Autostart ohne deine Zustimmung, kein Widerspruch gegen Deinstallation, kein Verstecken."
    };

    /// <summary>Grenzen — was SENTINEL ausdrücklich NICHT kann.</summary>
    public static readonly string[] Limitations =
    {
        "Kein Ersatz für Windows Defender oder ein Antivirenprogramm.",
        "Kann keine manipulierte Firmware, keinen Hardware-Keylogger und keinen Angreifer erkennen, der bereits vollen physischen Zugriff hat.",
        "Online-Prüfungen zeigen nur, was die jeweilige Datenbank kennt — eine unbekannte Bedrohung wird nicht gefunden.",
        "Der Sicherheits-Score ist eine Orientierung, keine Zertifizierung. Ein hoher Score ist kein Beweis für absolute Sicherheit."
    };

    /// <summary>
    /// Kurzfassung der Lizenz für den Info-Dialog. Der vollständige Text
    /// liegt in der Datei LICENSE im Projekt.
    /// </summary>
    public const string LicenseShort =
        "SENTINEL — Proprietäre Nutzungslizenz\n\n" +
        "Copyright (c) 2026 Felix Greis (Alias: Elian). Alle Rechte vorbehalten.\n\n" +
        "ERLAUBT\n" +
        "  • Private, nicht-kommerzielle Nutzung\n" +
        "  • Installation und Betrieb auf eigenen Geräten\n" +
        "  • Sicherungskopie für die bestimmungsgemäße Nutzung\n\n" +
        "UNTERSAGT (ohne schriftliche Genehmigung)\n" +
        "  • Vervielfältigen, Verbreiten, Veröffentlichen\n" +
        "  • Verändern, Bearbeiten, Übersetzen\n" +
        "  • Fork — als Grundlage eines eigenen Programms\n" +
        "  • Weitergabe an Dritte, Vermieten, Verpfänden\n" +
        "  • Entfernen von Urheberrechts- oder Branding-Vermerken\n" +
        "  • Reverse Engineering, Dekompilierung (soweit nicht Recht erzwingt)\n" +
        "  • Kommerzielle Nutzung\n" +
        "  • Bündelung mit anderer Software\n\n" +
        "KOMMERZIELLE NUTZUNG\n" +
        "  Nur auf Anfrage und mit gesonderter schriftlicher Lizenz.\n\n" +
        "DATENSCHUTZ\n" +
        "  Keine Telemetrie, kein Tracking. Alle Daten bleiben lokal.\n" +
        "  Online-Prüfungen nur nach Einwilligung — übertragen werden\n" +
        "  ausschließlich die geprüfte Adresse oder der SHA-256-Hash.\n" +
        "  Rechtsgrundlage: Art. 6 Abs. 1 lit. a, f DSGVO; § 25 TDDDG.\n\n" +
        "RECHT\n" +
        "  Recht der Bundesrepublik Deutschland, Stand 2026.\n" +
        "  Anwendbar: UrhG (§§ 31, 69a ff.), BGB, DSGVO, TDDDG.\n\n" +
        "Der vollständige Lizenztext steht in der Datei LICENSE im Projekt.";

    /// <summary>Lizenz-Art für die Anzeige (früher MIT).</summary>
    public const string LicenseName = "Proprietäre Nutzungslizenz (nur privat)";

    /// <summary>Eine Zeile des Änderungsprotokolls.</summary>
    public sealed record ChangelogEntry(string Version, string Date, string[] Changes);

    /// <summary>Änderungsprotokoll, neueste Version zuerst.</summary>
    public static readonly ChangelogEntry[] Changelog =
    {
        new("2.5 Beta", "12.10.2026", new[]
        {
            "5 wählbare Designs (Sentinel Dark, Midnight, DeepSpace, Solarized, Mono) — zur Laufzeit umschaltbar",
            "Info-Dialog: Lizenz, Beschreibung, Konzept, Grenzen und Änderungsprotokoll",
            "Integriertes Handbuch mit Schritt-für-Schritt-Anleitungen direkt im Programm",
            "5 neue Prüfungen: Windows-Hello-Verfügbarkeit, Defender-Tamper-Schutz, Papierkorb-Größe, Windows-Sandbox, WSL-Status",
            "Lizenz geändert: proprietäre Nutzungslizenz — private Nutzung erlaubt, kommerziell nur auf Anfrage",
            "Härtung: PowerShell-Aufrufe laufen über stdin statt über die Kommandozeile (keine Injection möglich)",
            "Fix: Admin-Rechte-Leck bei unbekanntem Nutzernamen",
            "Fix: Passwort-Ändern schlug immer fehl (falscher CurrentUser)"
        }),
        new("2.3 Beta", "12.10.2026", new[]
        {
            "Reset-Erkennung: nach einem Windows-Reset wird eine Neueinrichtung erzwungen",
            "8 neue Prüfungen (Ports, Dateierweiterungen, Systemwiederherstellung, NTFS-Zugriffszeiten, Wiederherstellungspartition, Update-Pause, Schnellstart, RDP-NLA)",
            "Autostart-Risiko-Analyse: Persistenz-Einträge werden nach Verdachtsmomenten bewertet",
            "HTML-Bericht-Export (XSS-sicher)"
        }),
        new("2.2 Beta", "12.10.2026", new[]
        {
            "Multi-User-System mit Rollen (Admin / Nutzer)",
            "Windows-Hello-Anmeldung (PIN, Gesicht, Fingerabdruck)",
            "Backup-Wiederherstellungscodes (2 Stück, gehasht gespeichert)",
            "Import lokaler Windows-Konten",
            "Letzter Admin gegen Löschen geschützt"
        }),
        new("2.0", "12.10.2026", new[]
        {
            "Multi-Datenbank-Bedrohungsanalyse (ThreatFox, MalwareBazaar, URLhaus, VirusTotal, Safe Browsing, OTX)",
            "31 lokale Prüfungen",
            "Datei-Prüfung (SHA-256) und Link-Prüfung"
        }),
        new("1.0", "12.10.2026", new[]
        {
            "Erste Version: Score-Berechnung, Basisprüfungen, Bericht-Export"
        })
    };

    /// <summary>Handbuch-Kapitel für den eingebauten Leitfaden.</summary>
    public sealed record ManualChapter(string Title, string[] Steps);

    /// <summary>Das eingebaute Handbuch.</summary>
    public static readonly ManualChapter[] Manual =
    {
        new("Erste Schritte", new[]
        {
            "SENTINEL herunterladen und starten. Beim ersten Start erscheint die Einrichtung.",
            "Einen Admin-Namen und ein starkes Passwort festlegen (mindestens 12 Zeichen, gemischt).",
            "Die zwei Backup-Codes werden angezeigt — schreibe sie auf und bewahre sie sicher auf. Sie werden nur dieses eine Mal gezeigt.",
            "Einrichtung abschließen. SENTINEL startet beim nächsten Mal mit der Anmeldesperre.",
            "Tipp: Rechtsklick und 'Als Administrator ausführen' gibt dir die meisten Prüfergebnisse. Ohne Admin-Rechte melden einzelne Prüfungen ehrlich 'unklar'."
        }),
        new("Anmelden", new[]
        {
            "Bei jedem Start erscheint die Sperre. Drei Wege sind möglich:",
            "1. Passwort des gewählten Nutzers eingeben.",
            "2. Windows Hello (PIN, Gesicht oder Fingerabdruck) — funktioniert nur für den Nutzer, der dem angemeldeten Windows-Konto entspricht.",
            "3. Backup-Code verwenden, wenn das Passwort vergessen wurde.",
            "Nach 5 falschen Versuchen ist das Konto für 15 Minuten gesperrt — das schützt vor automatischem Durchprobieren."
        }),
        new("Die Übersicht lesen", new[]
        {
            "Der große Ring in der Mitte ist der Sicherheits-Score von 0 bis 100.",
            "Grün (70+): gut. Gelb (40–69): Verbesserungsbedarf. Rot (unter 40 oder eine einzelne schwere Warnung): kritisch.",
            "Darunter stehen die Prüfungen, gruppiert nach Kategorie: Bestanden, Hinweis, Problem, Unklar.",
            "Jede Prüfung hat eine Erklärung (Warum zählt das?) und nächste Schritte. Lass sie dir anzeigen — sie erklären das Was und das Wie.",
            "Unklar bedeutet: SENTINEL konnte es nicht prüfen. Das ist meist ein Rechte-Problem. Als Administrator starten hilft."
        }),
        new("Eine Prüfung starten", new[]
        {
            "Den Button 'Prüfung starten' auf der Übersicht klicken.",
            "In den Einstellungen wählst du vorher die Tiefe: Schnell (nur die wichtigsten), Standard, oder Tiefenprüfung (alle 48 Checks).",
            "Während der Prüfung erscheint für jede Gruppe ein Fortschrittspunkt. Abbrechen ist jederzeit möglich — was schon geprüft ist, bleibt sichtbar.",
            "Das Ergebnis kannst du als HTML-Bericht exportieren. Der HTML-Bericht ist zum Ausdrucken und Weitergeben gedacht."
        }),
        new("Links und Dateien prüfen", new[]
        {
            "LinkShield: Eine Web-Adresse einfügen und prüfen. SENTINEL fragt mehrere Bedrohungsdatenbanken ab.",
            "FileShield: Eine Datei wählen. Es wird ihr SHA-256-Hash berechnet und geprüft — der Dateiinhalt verlässt deinen PC nie.",
            "Vor der ersten Online-Prüfung erscheint ein Einwilligungsdialog. Er sagt genau, was übertragen wird (nur Adresse oder Hash).",
            "Ohne Einwilligung bleiben die Prüfungen lokal. In den Einstellungen lässt sich die Einwilligung jederzeit widerrufen."
        }),
        new("Nutzer und Rollen verwalten", new[]
        {
            "Nur Admins sehen die Seite Nutzer und Rollen. Normale Nutzer sehen sie nicht.",
            "Nutzer hinzufuegen legt ein Konto mit Passwort an. Die Stärke wird live angezeigt.",
            "Windows-Konten importieren übernimmt vorhandene lokale Windows-Benutzer als SENTINEL-Nutzer (Rolle: Nutzer).",
            "Admins können Rollen ändern und Nutzer löschen — den letzten Admin aber nicht. Das verhindert, dass sich alle aus dem System aussperren.",
            "Jeder Nutzer hat sein eigenes Passwort. Ein Admin kann das Passwort eines Nutzers zurücksetzen, wenn er sein eigenes eingibt."
        }),
        new("Design wechseln", new[]
        {
            "Einstellungen → Erscheinungsbild → Design.",
            "Fünf Designs stehen bereit: Sentinel Dark (Standard), Midnight (Nachtblau), DeepSpace (Neon-Grün), Solarized (Sepia) und Mono.",
            "Mono ist komplett farbfrei — Schwarz auf Weiß, gedacht für maximale Lesbarkeit und bei Farbsehschwäche.",
            "Die Wahl wirkt sofort und wird gespeichert. Nach dem nächsten Start ist sie wieder da."
        }),
        new("Backup-Codes verwenden", new[]
        {
            "Auf der Sperre den Backup-Code-Weg wählen.",
            "Einen der beiden Codes eingeben und ein neues Passwort festlegen.",
            "Der Code wird dabei verbraucht — er funktioniert nur einmal.",
            "Sobald ein Code benutzt ist, erzeugt ein Admin neue Codes auf der Seite Nutzer und Rollen."
        }),
        new("Was SENTINEL nicht kann", new[]
        {
            "Es ist kein Antivirenprogramm und ersetzt Windows Defender nicht.",
            "Es erkennt keinen Angreifer mit physischem Zugriff auf den PC und keine manipulierte Hardware.",
            "Es kann eine unbekannte, noch nicht gemeldete Bedrohung nicht finden.",
            "Es sperrt den PC nicht bei Deinstallation und überlebt keinen Windows-Reset — beides absichtlich, damit das System immer dein letzter Rettungsweg bleibt."
        })
    };

    /// <summary>Kurzer Einleitungstext für den Info-Dialog.</summary>
    public static string Summary =>
        $"SENTINEL {Branding.FullVersion} — {Branding.Tagline}\n" +
        $"© {Branding.Author} (Alias: {Branding.AuthorAlias})\n" +
        $"Lizenz: {LicenseName} — {Manual.Length} Handbuch-Kapitel, {Changelog.Length} Versionen im Protokoll.";
}
