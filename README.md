# SENTINEL
SENTINEL is a modern, privacy-focused security assistant designed to make digital security simple, transparent, and accessible to everyone. It aims to help users assess their system’s security, identify potential risks, analyze suspicious links, and improve their security settings through clear recommendations and guided checks.


---

## Deutsch / Projektstand (Felix Greis — Alias: Elian)

Version **2.3 Beta**. 43 lokale Checks, Multi-User mit Rollen, Windows-Hello, Backup-Codes, Multi-DB-Bedrohungsanalyse.

```
dotnet build src/Sentinel.App/Sentinel.App.csproj -p:EnableWindowsTargeting=true -c Release
dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj
dotnet publish src/Sentinel.App/Sentinel.App.csproj -p:EnableWindowsTargeting=true -c Release -r win-x64 --self-contained true -o dist/SENTINEL-win-x64
```

Aufbau:
- `src/Sentinel.Core` — Logik, Parser, Scoring, Nutzer, ThreatIntel (plattformunabhängig)
- `src/Sentinel.Platform` — Datenerfassung via PowerShell/WMI/Registry/WinRT (read-only)
- `src/Sentinel.App` — WPF-Oberfläche
- `tests/Sentinel.Tests` — 200 Tests

Alle Prüfungen sind read-only. Online-Prüfungen laufen nur nach ausdrücklicher Einwilligung und senden ausschließlich URL oder Hash — niemals Dateiinhalte oder Dateinamen.

Details: `ANLEITUNG.md`
