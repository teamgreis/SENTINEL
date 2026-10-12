using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft Windows Hello / Biometrie-Verfügbarkeit. Read-only.</summary>
public sealed class WindowsHelloCheck : ICheck
{
    public string Id => "system.windowshello";
    public string Title => "Windows Hello";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft, ob eine biometrische oder PIN-Anmeldung eingerichtet ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$p = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue; " +
                "$h = Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Biometrics' -ErrorAction SilentlyContinue; " +
                "$b = Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Biometric -ErrorAction SilentlyContinue; " +
                "$c = @(Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers' -ErrorAction SilentlyContinue).Count; " +
                "\"$($b.Count)|$($h.PSObject.Properties.Name -contains 'Enabled')|$c\"",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();
            var parts = combined.Split('|');

            int biometricCount = parts.Length > 0 && int.TryParse(parts[0], out var bc) ? bc : -1;
            bool policySet = parts.Length > 1 && parts[1].Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            int providerCount = parts.Length > 2 && int.TryParse(parts[2], out var pc) ? pc : -1;

            bool hasBiometrics = biometricCount > 0;
            bool hasProviders = providerCount > 0;

            if (hasBiometrics || hasProviders)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = hasBiometrics
                        ? "Biometrische Anmeldung ist verfügbar."
                        : "Anmelde-Verfahren (z. B. PIN) sind eingerichtet.",
                    Explanation = "Windows Hello mit PIN oder Biometrie ist komfortabler als ein Tipp-Passwort und gleichzeitig sicher – der Schlüssel bleibt im TPM.",
                    Source = "Registry/Win32_Biometric"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Info,
                Detail = "Keine biometrische oder PIN-Anmeldung eingerichtet.",
                Explanation = "Du kannst unter Einstellungen → Konten → Anmeldeoptionen eine PIN oder (bei unterstützter Hardware) Fingerabdruck/Gesicht einrichten.",
                RecommendedActions = new[]
                {
                    "Einstellungen → Konten → Anmeldeoptionen.",
                    "PIN hinzufügen (sicherer als ein Passwort, weil der Schlüssel im TPM liegt)."
                },
                Source = "Registry/Win32_Biometric"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Unknown,
                Detail = "Prüfung nicht möglich: " + ex.Message,
                Explanation = "Windows-Hello-Status ist nicht ermittelbar – meist weil die Abfrage blockiert wurde.",
                Source = "Registry/Win32_Biometric"
            };
        }
    }
}
