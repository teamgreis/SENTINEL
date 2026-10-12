using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft, ob Letzte-Zugriff-Zeitstempel (MAC-Times) aktiviert sind. Read-only.</summary>
public sealed class NtfsLastAccessCheck : ICheck
{
    public string Id => "system.ntfslastaccess";
    public string Title => "NTFS-Zugriffszeiten";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft, ob Dateizugriffe protokolliert werden (forensisch relevant).";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync("fsutil behavior query DisableLastAccess", ct).ConfigureAwait(false);
            string combined = (output + " " + error).ToLowerInvariant();

            if (combined.Contains("disablelastaccess = 1") || combined.Contains("disablelastaccess = 1"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Info,
                    Detail = "Zugriffszeiten sind deaktiviert (Windows-Standard seit Vista).",
                    Explanation = "Windows protokolliert standardmäßig nicht mehr, wann eine Datei zuletzt gelesen wurde. Für forensische Analysen nach einem Vorfall ist das ein Nachteil.",
                    Source = "fsutil behavior"
                };
            }

            if (combined.Contains("disablelastaccess = 0"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Zugriffszeiten werden protokolliert.",
                    Explanation = "Dateizugriffe werden mit Zeitstempel festgehalten – nützlich, um nach einem Vorfall nachzuvollziehen, wer was wann gelesen hat.",
                    Source = "fsutil behavior"
                };
            }

            return Unknown();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown() => new()
    {
        Id = "system.ntfslastaccess", Title = "NTFS-Zugriffszeiten", Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown,
        Detail = "Nicht abfragbar.",
        Explanation = "In einer Admin-PowerShell: fsutil behavior query DisableLastAccess.",
        Source = "fsutil behavior"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
