using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft die Größe des Papierkorbs (versteckter Speicherfresser). Read-only.</summary>
public sealed class RecycleBinSizeCheck : ICheck
{
    public string Id => "system.recyclebin";
    public string Title => "Papierkorb-Größe";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft, wie viel Platz der Papierkorb belegt.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$s = (Get-ChildItem 'C:\\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; " +
                "if ($s) { [math]::Round($s/1MB,0) } else { 0 }",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();
            int mb = int.TryParse(combined.Split('\n')[0].Trim(), out var m) ? m : -1;

            if (mb < 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Unknown,
                    Detail = "Papierkorb-Größe nicht abfragbar.",
                    Explanation = "Der Papierkorb auf Laufwerk C: kann Speicher belegen. Zum Leeren: Rechtsklick auf dem Desktop → Papierkorb leeren.",
                    Source = "Get-ChildItem"
                };
            }

            if (mb > 2000)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = $"Papierkorb belegt {mb:N0} MB.",
                    Explanation = "Gelöschte Dateien liegen noch im Papierkorb und belegen Speicher. Sie sind auch nach dem Löschen wiederherstellbar — sensible Daten solltest du gezielt vernichten.",
                    RecommendedActions = new[]
                    {
                        "Papierkorb leeren: Rechtsklick auf dem Desktop.",
                        "Für sensible Daten: sicheres Löschen verwenden (z. B. cipher /w oder SDelete)."
                    },
                    Source = "Get-ChildItem"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = mb == 0 ? "Papierkorb ist leer." : $"Papierkorb belegt {mb:N0} MB.",
                Explanation = "Das ist unauffällig. Denk bei sensiblen Daten daran: Löschen verschiebt nur in den Papierkorb.",
                Source = "Get-ChildItem"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.recyclebin", Title = "Papierkorb-Größe", Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe den Papierkorb manuell auf dem Desktop.",
        Source = "Get-ChildItem"
    };
}
