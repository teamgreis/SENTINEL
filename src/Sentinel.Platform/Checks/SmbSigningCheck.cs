using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft die SMB-Signatur. Ohne Signatur können Angreifer SMB-Verkehr
/// im Netzwerk manipulieren (Man-in-the-Middle).
/// </summary>
public sealed class SmbSigningCheck : ICheck
{
    public string Id => "network.smbsigning";
    public string Title => "SMB-Signatur";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob SMB-Verkehr signiert werden muss.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(Get-SmbServerConfiguration).RequireSecuritySignature", ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim().ToLowerInvariant();

            if (combined.Contains("true") || combined.Contains("1"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "SMB-Signatur ist erforderlich.",
                    Explanation = "SMB-Verkehr im Netzwerk wird signiert – Manipulation durch Angreifer im gleichen Netzwerk wird erkannt.",
                    Source = "Get-SmbServerConfiguration"
                };
            }

            if (combined.Contains("false") || combined.Contains("0"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "SMB-Signatur ist nicht erforderlich.",
                    Explanation = "Ohne Signatur kann ein Angreifer im gleichen Netzwerk SMB-Verkehr manipulieren und Dateien oder Anmeldedaten abfangen.",
                    RecommendedActions = new[]
                    {
                        "Als Administrator: Set-SmbServerConfiguration -RequireSecuritySignature $true",
                        "Oder in gpedit.msc → Computerkonfiguration → Administrative Vorlagen → Netzwerk → Lanman-Arbeitsstation: 'Sicherheitssignatur immer erforderlich'."
                    },
                    Source = "Get-SmbServerConfiguration"
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
        Id = "network.smbsigning", Title = "SMB-Signatur", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = "SMB-Signatur nicht abfragbar.",
        Explanation = "Für Heimnetzwerke mit einer NAS relevant. Prüfe in gpedit.msc die Lanman-Einstellungen.",
        Source = "Get-SmbServerConfiguration"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
