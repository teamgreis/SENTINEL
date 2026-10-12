using System.Text.Json;

namespace Sentinel.Core.Integrity;

/// <summary>
/// Erkennt einen Windows-Reset („Diesen PC zurücksetzen").
/// Nach einem Reset sind die Nutzerdaten in %ProgramData% bzw. %LOCALAPPDATA%
/// gelöscht, aber das Programm selbst läuft noch. SENTINEL soll dann
/// NICHT einfach mit leeren Daten starten, sondern den Nutzer zwingen,
/// neu einzurichten – und den Reset als Ereignis protokollieren.
/// </summary>
public sealed class ResetDetector
{
    /// <summary>Marker-Datei: beweist, dass SENTINEL einmal eingerichtet war.</summary>
    public const string MarkerFileName = "installed.marker";

    private readonly string _dataDir;

    public ResetDetector(string dataDir) => _dataDir = dataDir;

    /// <summary>
    /// Ergebnis der Reset-Prüfung.
    /// </summary>
    public sealed record ResetCheckResult(
        bool IsFreshInstall,
        bool WasReset,
        string Message);

    /// <summary>
    /// Prüft, ob ein Reset stattgefunden hat.
    /// Logik: Der Marker liegt NEBEN den Nutzerdaten. Wenn der Marker da ist,
    /// aber die Nutzerdaten fehlen → Reset. Wenn beides fehlt → frische Installation.
    /// </summary>
    public ResetCheckResult Check(bool hasUserData)
    {
        string markerPath = Path.Combine(_dataDir, MarkerFileName);
        bool markerExists = File.Exists(markerPath);

        if (!hasUserData && !markerExists)
        {
            // Alles weg → frische Installation (normaler Onboarding-Fall)
            return new ResetCheckResult(true, false,
                "Erste Einrichtung – kein vorheriger Stand gefunden.");
        }

        if (!hasUserData && markerExists)
        {
            // Marker da, aber Nutzer weg → Reset
            return new ResetCheckResult(false, true,
                "Windows-Reset erkannt: Die SENTINEL-Daten wurden gelöscht, " +
                "das Programm aber nicht. Eine Neueinrichtung ist erforderlich.");
        }

        // Nutzerdaten vorhanden → normaler Start, Marker sicherstellen
        if (!markerExists)
            MarkInstalled();

        return new ResetCheckResult(false, false, "Normaler Start.");
    }

    /// <summary>Setzt den Installations-Marker (nach erfolgreichem Onboarding).</summary>
    public void MarkInstalled()
    {
        try
        {
            Directory.CreateDirectory(_dataDir);
            var info = new
            {
                installedAt = DateTimeOffset.UtcNow,
                version = Core.Branding.FullVersion,
                machine = Environment.MachineName
            };
            File.WriteAllText(Path.Combine(_dataDir, MarkerFileName),
                JsonSerializer.Serialize(info));
        }
        catch
        {
            // Marker darf nichts blockieren
        }
    }

    /// <summary>Löscht den Marker (z. B. bei Deinstallation).</summary>
    public void RemoveMarker()
    {
        try
        {
            string path = Path.Combine(_dataDir, MarkerFileName);
            if (File.Exists(path)) File.Delete(path);
        }
        catch { }
    }
}
