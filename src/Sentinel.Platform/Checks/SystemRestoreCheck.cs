using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft, ob die Systemwiederherstellung aktiv ist (Recovery-Punkte). Read-only.</summary>
public sealed class SystemRestoreCheck : ICheck
{
    public string Id => "system.systemrestore";
    public string Title => "Systemwiederherstellung";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft, ob Wiederherstellungspunkte angelegt werden.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Measure-Object).Count",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();
            int count = int.TryParse(combined.Split('\n')[0].Trim(), out var c) ? c : -1;

            if (count > 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = $"{count} Wiederherstellungspunkt(e) vorhanden.",
                    Explanation = "Mit Wiederherstellungspunkten kannst du Windows auf einen früheren Stand zurücksetzen, wenn etwas kaputtgeht.",
                    Source = "Get-ComputerRestorePoint"
                };
            }

            if (count == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "Keine Wiederherstellungspunkte vorhanden.",
                    Explanation = "Ohne Wiederherstellungspunkte gibt es keinen einfachen Weg zurück, wenn ein Update oder Programm Windows beschädigt.",
                    RecommendedActions = new[]
                    {
                        "Systemsteuerung → System → Computerschutz → Konfigurieren.",
                        "Systemschutz für Laufwerk C: aktivieren."
                    },
                    Source = "Get-ComputerRestorePoint"
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
        Id = "system.systemrestore", Title = "Systemwiederherstellung", Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown,
        Detail = "Status nicht abfragbar.",
        Explanation = "Prüfe in der Systemsteuerung → System → Computerschutz.",
        Source = "Get-ComputerRestorePoint"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
