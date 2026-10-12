using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft, ob der Windows-Explorer Dateierweiterungen anzeigt. Read-only.</summary>
public sealed class FileExtensionsCheck : ICheck
{
    public string Id => "system.fileextensions";
    public string Title => "Dateierweiterungen";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob Dateierweiterungen im Explorer sichtbar sind.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -ErrorAction SilentlyContinue).HideFileExt",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();

            if (combined.Contains("1") || combined.Contains("true"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "Dateierweiterungen sind ausgeblendet.",
                    Explanation = "Ohne sichtbare Endungen sieht 'Rechnung.pdf.exe' wie 'Rechnung.pdf' aus – ein klassischer Trick, um Schadsoftware als harmlose Datei zu tarnen.",
                    RecommendedActions = new[]
                    {
                        "Explorer → Ansicht → Anzeigen → Dateinamenerweiterungen aktivieren.",
                        "Oder Registry: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced → HideFileExt = 0"
                    },
                    Source = "Registry (HideFileExt)"
                };
            }

            if (combined.Contains("0") || combined.Contains("false"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Dateierweiterungen werden angezeigt.",
                    Explanation = "Doppelte Endungen wie '.pdf.exe' sind sofort erkennbar – ein wichtiger Schutz gegen getarnte Schadsoftware.",
                    Source = "Registry (HideFileExt)"
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
        Id = "system.fileextensions", Title = "Dateierweiterungen", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = "Einstellung nicht abfragbar.",
        Explanation = "Prüfe im Explorer: Ansicht → Anzeigen → Dateinamenerweiterungen.",
        Source = "Registry (HideFileExt)"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
