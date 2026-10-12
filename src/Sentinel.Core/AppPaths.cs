namespace Sentinel.Core;

/// <summary>
/// Zentrale Pfad-Verwaltung. Bevorzugt wird der systemweite Ordner
/// (%ProgramData%\SENTINEL), wenn die App dort schreiben darf (also
/// wenn sie mit Admin-Rechten läuft). Sonst der nutzerlokale Ordner.
/// So sind Daten „systemweit" nutzbar, ohne dass ein Normalnutzer
/// die Rechte dafür braucht.
/// </summary>
public static class AppPaths
{
    /// <summary>Basisordner für alle SENTINEL-Daten.</summary>
    public static string DataDir { get; } = ResolveDataDir();

    /// <summary>Pfad einer Datendatei im Basisordner.</summary>
    public static string PathFor(string fileName) => Path.Combine(DataDir, fileName);

    private static string ResolveDataDir()
    {
        try
        {
            string programData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                Branding.ProductName);

            Directory.CreateDirectory(programData);

            // Schreibprobe – scheitert sie (keine Rechte), nutzen wir den Nutzerordner
            string probe = Path.Combine(programData, ".write-test");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);

            return programData;
        }
        catch
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Branding.ProductName);
        }
    }
}
