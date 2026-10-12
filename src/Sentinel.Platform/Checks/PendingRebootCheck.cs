using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft, ob Windows seit dem letzten Update neu gestartet wurde.
/// Hängende Updates = bekannte Angriffsfläche.
/// </summary>
public sealed class PendingRebootCheck : ICheck
{
    public string Id => "system.pendingreboot";
    public string Title => "Ausstehender Neustart";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob Windows auf einen Neustart wartet.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$flags = @(); " +
                "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') { $flags += 'CBS' }; " +
                "if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') { $flags += 'WU' }; " +
                "$f = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -ErrorAction SilentlyContinue; " +
                "if ($f.PendingFileRenameOperations) { $flags += 'FileRename' }; " +
                "if ($flags.Count -gt 0) { $flags -join ',' } else { 'keiner' }",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();

            if (combined.Contains("keiner") || combined.Length == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Kein ausstehender Neustart.",
                    Explanation = "Alle installierten Updates sind wirksam. Sicherheitslücken in aktualisierten Komponenten sind geschlossen.",
                    Source = "Registry (RebootPending)"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Warning,
                Detail = $"Windows wartet auf einen Neustart (Grund: {combined}).",
                Explanation = "Installierte Sicherheitsupdates werden erst nach dem Neustart wirksam. Bis dahin sind die geschlossenen Lücken noch offen.",
                RecommendedActions = new[]
                {
                    "PC neu starten, um alle Updates zu aktivieren.",
                    "Unter Windows Update prüfen, ob weitere Updates ausstehen."
                },
                Source = "Registry (RebootPending)"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.pendingreboot", Title = "Ausstehender Neustart", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe im Startmenü (Ein/Aus), ob 'Update und neu starten' angeboten wird.",
        Source = "Registry (RebootPending)"
    };
}
