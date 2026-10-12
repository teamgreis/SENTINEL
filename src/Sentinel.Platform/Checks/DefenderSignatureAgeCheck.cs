using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft den Windows-Speicherort der Defender-Signaturen.
/// Bei sehr alten Signaturen ist der Echtzeitschutz eingeschränkt.
/// </summary>
public sealed class DefenderSignatureAgeCheck : ICheck
{
    public string Id => "system.defendersignature";
    public string Title => "Defender-Signaturen";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft das Alter der Defender-Virensignaturen.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$s = Get-MpComputerStatus; \"$($s.AntivirusSignatureLastUpdated)|$($s.AntispywareSignatureLastUpdated)|$($s.AMServiceEnabled)\"",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();
            var parts = combined.Split('|');

            if (parts.Length < 2 || !DateTime.TryParse(parts[0].Trim(), out var lastUpdate))
                return Unknown("Signaturdatum nicht lesbar.");

            int days = (int)(DateTime.Now - lastUpdate).TotalDays;

            if (days > 14)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = $"Defender-Signaturen sind {days} Tage alt (Stand {lastUpdate:dd.MM.yyyy}).",
                    Explanation = "Virensignaturen erkennen nur, was in ihnen steht. Alte Signaturen = Schutzlücke gegen neue Schadsoftware.",
                    RecommendedActions = new[]
                    {
                        "Windows-Sicherheit → Virus- und Bedrohungsschutz → Nach Updates suchen.",
                        "Falls das Update fehlschlägt: PC mit einem zweiten Scanner (z. B. Notfall-DVD) prüfen."
                    },
                    Source = "Get-MpComputerStatus"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = $"Defender-Signaturen sind aktuell ({days} Tage alt, Stand {lastUpdate:dd.MM.yyyy}).",
                Explanation = "Windows lädt die Signaturen täglich automatisch. Aktuelle Signaturen erkennen neue Schadsoftware.",
                Source = "Get-MpComputerStatus"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.defendersignature", Title = "Defender-Signaturen", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe in der Windows-Sicherheit unter Virus- und Bedrohungsschutz das Signaturdatum.",
        Source = "Get-MpComputerStatus"
    };
}
