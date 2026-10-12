using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft das SMBv1-Protokoll. SMBv1 hat bekannte, schwerwiegende Schwachstellen
/// (EternalBlue/WannaCry) und sollte deaktiviert sein.
/// </summary>
public sealed class SmbV1Check : ICheck
{
    public string Id => "network.smbv1";
    public string Title => "SMBv1-Protokoll";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob das veraltete SMBv1-Protokoll aktiv ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(Get-SmbServerConfiguration).EnableSMB1Protocol",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 } && output.Length == 0)
                return Unknown("Die SMB-Konfiguration konnte nicht gelesen werden.");

            bool smb1Enabled = output.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);

            if (smb1Enabled)
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Fail,
                    Detail = "SMBv1 ist aktiviert.",
                    Explanation = "SMBv1 ist ein veraltetes Protokoll mit bekannten, schwerwiegenden Sicherheitslücken (u. a. ausgenutzt von WannaCry). Es sollte nur aktiv sein, wenn sehr alte Geräte im Netzwerk es zwingend brauchen.",
                    RecommendedActions = new[]
                    {
                        "Systemsteuerung → Programme → Windows-Features aktivieren oder deaktivieren.",
                        "Haken bei „Unterstützung des SMB 1.0/CIFS-Dateifreigabeprotokolls“ entfernen.",
                        "PC neu starten."
                    },
                    Source = "Get-SmbServerConfiguration"
                };

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = "SMBv1 ist deaktiviert.",
                Explanation = "Das moderne SMB-Protokoll ist aktiv, das angreifbare SMBv1 ist aus. Gut so.",
                Source = "Get-SmbServerConfiguration"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("SMB-Status konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "network.smbv1",
        Title = "SMBv1-Protokoll",
        Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Prüfe manuell: Systemsteuerung → Programme → Windows-Features → „Unterstützung des SMB 1.0/CIFS-Dateifreigabeprotokolls“ sollte deaktiviert sein.",
        Source = "Get-SmbServerConfiguration"
    };
}
