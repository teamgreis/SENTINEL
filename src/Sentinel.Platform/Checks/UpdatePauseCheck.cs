using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft die Windows-Update-Pause. Read-only.</summary>
public sealed class UpdatePauseCheck : ICheck
{
    public string Id => "system.updatepause";
    public string Title => "Update-Pause";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob Windows Updates pausiert sind.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$k = 'HKLM:\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings'; " +
                "if (Test-Path $k) { \"$((Get-ItemProperty $k).PauseUpdatesExpiryTime)|$((Get-ItemProperty $k).PauseFeatureUpdatesEndTime)\" } else { 'keine pause' }",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();

            if (combined.Contains("keine pause") || combined.Length == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Updates sind nicht pausiert.",
                    Explanation = "Sicherheitsupdates kommen automatisch. Lücken werden zeitnah geschlossen.",
                    Source = "Registry (WindowsUpdate/UX)"
                };
            }

            var parts = combined.Split('|');
            string? expiry = parts.Length > 0 ? parts[0].Trim() : null;

            if (!string.IsNullOrEmpty(expiry) && expiry != "0" && expiry != "null")
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "Windows Updates sind pausiert.",
                    Explanation = "Pausierte Updates bedeuten: bekannte Sicherheitslücken bleiben länger offen. Maximal 35 Tage sind erlaubt, danach erzwingt Windows das Update.",
                    RecommendedActions = new[]
                    {
                        "Einstellungen → Windows Update → Updates fortsetzen."
                    },
                    Source = "Registry (WindowsUpdate/UX)"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = "Keine aktive Update-Pause erkannt.",
                Explanation = "Updates laufen normal.",
                Source = "Registry (WindowsUpdate/UX)"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.updatepause", Title = "Update-Pause", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe unter Einstellungen → Windows Update, ob Updates pausiert sind.",
        Source = "Registry (WindowsUpdate/UX)"
    };
}
