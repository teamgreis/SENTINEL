using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft die Anzahl der Wiederherstellungs-/Systempartitionen (Reset-Rettung). Read-only.</summary>
public sealed class RecoveryPartitionCheck : ICheck
{
    public string Id => "system.recoverypartition";
    public string Title => "Wiederherstellungspartition";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft, ob eine Wiederherstellungspartition für den Notfall existiert.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(Get-Partition | Where-Object { $_.Type -eq 'Recovery' } | Measure-Object).Count",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();
            int count = int.TryParse(combined.Split('\n')[0].Trim(), out var c) ? c : -1;

            if (count > 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = $"{count} Wiederherstellungspartition(en) vorhanden.",
                    Explanation = "Die Wiederherstellungspartition enthält das Notfall-Windows. Damit kannst du den PC auch ohne funktionierendes System reparieren.",
                    Source = "Get-Partition"
                };
            }

            if (count == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "Keine Wiederherstellungspartition gefunden.",
                    Explanation = "Ohne Wiederherstellungspartition ist eine Reparatur über den Boot-Manager nicht möglich. Bei einem Windows-Reset werden die Daten dann vollständig gelöscht.",
                    RecommendedActions = new[]
                    {
                        "Windows-Wiederherstellungslaufwerk erstellen (recoverydrive.exe).",
                        "Oft hat der Hersteller die Partition verkleinert/gelöscht."
                    },
                    Source = "Get-Partition"
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
        Id = "system.recoverypartition", Title = "Wiederherstellungspartition", Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown,
        Detail = "Nicht abfragbar.",
        Explanation = "Prüfe in der Datenträgerverwaltung (diskmgmt.msc) nach einer 'Wiederherstellung'-Partition.",
        Source = "Get-Partition"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
