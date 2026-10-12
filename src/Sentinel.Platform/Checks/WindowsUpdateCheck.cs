using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft das Alter des letzten installierten Updates über Get-HotFix.
/// Funktioniert als normaler Benutzer (der alte Registry-Wert
/// „LastSuccessTime“ existiert auf modernen Systemen nicht zuverlässig).
/// </summary>
public sealed class WindowsUpdateCheck : ICheck
{
    private const int MaxAgeDays = 30;

    public string Id => "system.updates";
    public string Title => "Windows-Updates";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => $"Prüft das Alter des letzten installierten Windows-Updates (Grenze: {MaxAgeDays} Tage).";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            // HotFix-Liste mit Installationsdatum holen
            var (output, error) = await PowerShell.RunAsync(
                "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID,InstalledOn | ConvertTo-Json -Compress",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 } && output.Length == 0)
                return Unknown("Die Update-Liste konnte nicht gelesen werden (eventuell blockiert durch Richtlinien).");

            if (!HotFixParser.TryParse(output, out var hotfix))
                return Unknown("Die Update-Informationen konnten nicht gelesen werden.");

            if (hotfix.InstalledOn is null)
                return Unknown("Es konnte kein Installationsdatum für Updates ermittelt werden.");

            int days = (int)(DateTime.Now - hotfix.InstalledOn.Value).TotalDays;
            string when = hotfix.InstalledOn.Value.ToString("dd.MM.yyyy");

            if (days > MaxAgeDays)
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = $"Letztes installiertes Update: {hotfix.HotFixId} vom {when} (vor {days} Tagen).",
                    Explanation = $"Windows-Updates schließen bekannt gewordene Sicherheitslücken. Ein Abstand von über {MaxAgeDays} Tagen kann riskant sein.",
                    RecommendedActions = new[]
                    {
                        "Einstellungen → Windows Update öffnen und „Nach Updates suchen“ ausführen.",
                        "„Updates erhalten für andere Microsoft-Produkte“ aktivieren, damit auch Office & Co. aktuell bleiben."
                    },
                    Source = "Get-HotFix"
                };

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = $"Letztes installiertes Update: {hotfix.HotFixId} vom {when} (vor {days} Tagen).",
                Explanation = "Dein System hat kürzlich Updates erhalten. Damit sind bekannte Sicherheitslücken weitgehend geschlossen.",
                Limitations = "Prüft nur das jüngste installierte Update, nicht ob alle verfügbaren Updates installiert sind.",
                Source = "Get-HotFix"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("Update-Status konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.updates",
        Title = "Windows-Updates",
        Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Das letzte Update-Datum konnte nicht ausgelesen werden. Prüfe es manuell unter Einstellungen → Windows Update.",
        RecommendedActions = new[]
        {
            "Einstellungen → Windows Update öffnen und den Status der letzten Updates kontrollieren."
        }
    };
}
