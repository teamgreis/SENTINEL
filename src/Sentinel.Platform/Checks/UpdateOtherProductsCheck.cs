using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft die Windows-Update-Politik für andere Microsoft-Produkte.
/// Ohne diese Einstellung werden nur Windows-Updates installiert.
/// </summary>
public sealed class UpdateOtherProductsCheck : ICheck
{
    public string Id => "system.updateotherproducts";
    public string Title => "Updates für andere Produkte";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft, ob Updates für Office und andere Microsoft-Produkte kommen.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -ErrorAction SilentlyContinue | ForEach-Object { $_.AllowMUUpdateService }",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim().ToLowerInvariant();

            if (combined.Contains("1") || combined.Contains("true"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Updates für andere Microsoft-Produkte sind aktiviert.",
                    Explanation = "Office, .NET und Co. bekommen ebenfalls automatisch Sicherheitsupdates.",
                    Source = "Registry (AllowMUUpdateService)"
                };
            }

            if (combined.Contains("0") || combined.Contains("false"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Info,
                    Detail = "Updates für andere Microsoft-Produkte sind deaktiviert.",
                    Explanation = "Nur Windows selbst bekommt Updates. Office-Lücken bleiben bis zum manuellen Update offen.",
                    RecommendedActions = new[]
                    {
                        "Einstellungen → Windows Update → Erweiterte Optionen.",
                        "\"Updates für andere Microsoft-Produkte erhalten\" aktivieren."
                    },
                    Source = "Registry (AllowMUUpdateService)"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Info,
                Detail = "Richtlinie nicht gesetzt (Standard: aktiv auf Home/Pro).",
                Explanation = "Falls Office-Updates fehlen: Einstellungen → Windows Update → Erweiterte Optionen → „Updates für andere Microsoft-Produkte erhalten“ prüfen.",
                Source = "Registry (AllowMUUpdateService)"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.updateotherproducts", Title = "Updates für andere Produkte", Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe in den Windows-Update-Einstellungen unter Erweiterte Optionen.",
        Source = "Registry (AllowMUUpdateService)"
    };
}
