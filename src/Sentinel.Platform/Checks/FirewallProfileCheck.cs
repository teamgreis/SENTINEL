using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft die drei Firewall-Profile (Domäne/Privat/Öffentlich). Read-only.</summary>
public sealed class FirewallProfileCheck : ICheck
{
    public string Id => "network.firewallprofiles";
    public string Title => "Firewall-Profile";
    public CheckWeight Weight => CheckWeight.High;
    public string Description => "Prüft alle drei Firewall-Profile einzeln.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "Get-NetFirewallProfile | ForEach-Object { \"$($_.Name):$($_.Enabled)\" }", ct).ConfigureAwait(false);

            string combined = (output + "\n" + error).Trim();
            var profiles = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

            foreach (var line in combined.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Trim().Split(':');
                if (parts.Length == 2)
                    profiles[parts[0].Trim()] = parts[1].Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            }

            if (profiles.Count == 0)
                return Unknown();

            var disabled = profiles.Where(p => !p.Value).Select(p => p.Key).ToList();

            if (disabled.Count == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = $"Alle {profiles.Count} Firewall-Profile sind aktiv ({string.Join(", ", profiles.Keys)}).",
                    Explanation = "Die Firewall filtert eingehende Verbindungen in jedem Netzwerktyp – auch in unbekannten WLANs.",
                    Source = "Get-NetFirewallProfile"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Fail,
                Detail = $"Deaktivierte Firewall-Profile: {string.Join(", ", disabled)}.",
                Explanation = "Ein deaktiviertes Profil lässt in diesem Netzwerktyp alle eingehenden Verbindungen durch – im eigenen WLAN wie auch in öffentlichen Netzen.",
                RecommendedActions = new[]
                {
                    "Einstellungen → Datenschutz und Sicherheit → Windows-Sicherheit → Firewall- und Netzwerkschutz.",
                    "Für jedes Netzwerkprofil (Domäne, Privat, Öffentlich) die Firewall aktivieren.",
                    "Oder als Administrator: netsh advfirewall set allprofiles state on"
                },
                Source = "Get-NetFirewallProfile"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown() => new()
    {
        Id = "network.firewallprofiles", Title = "Firewall-Profile", Weight = CheckWeight.High,
        Status = CheckStatus.Unknown,
        Detail = "Firewall-Profile nicht abfragbar (Modul NetSecurity blockiert?).",
        Explanation = "Prüfe manuell in den Windows-Sicherheitseinstellungen.",
        Source = "Get-NetFirewallProfile"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
