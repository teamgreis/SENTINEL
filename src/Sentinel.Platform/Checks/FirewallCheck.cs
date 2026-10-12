using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft den Status der Windows-Firewall für die drei Profile.
/// Read-only: liest NetSecurity-Modul per PowerShell.
/// </summary>
public sealed class FirewallCheck : ICheck
{
    public string Id => "system.firewall";
    public string Title => "Windows-Firewall";
    public CheckWeight Weight => CheckWeight.High;
    public string Description => "Prüft, ob die Windows-Firewall für alle Netzwerkprofile aktiv ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 })
                return Unknown("Firewall-Status konnte nicht gelesen werden. (Ausführlich im Bericht)");

            var profiles = ParseProfiles(output);
            if (profiles.Count == 0)
                return Unknown("Es wurden keine Firewall-Profile gefunden.");

            var disabled = profiles.Where(p => !p.Enabled).Select(p => NameOf(p.Name)).ToList();
            bool allEnabled = disabled.Count == 0;

            return new CheckResult
            {
                Id = Id,
                Title = Title,
                Weight = Weight,
                Status = allEnabled ? CheckStatus.Pass : CheckStatus.Fail,
                Detail = allEnabled
                    ? "Die Firewall ist in allen Netzwerkprofilen aktiv."
                    : $"Die Firewall ist deaktiviert in: {string.Join(", ", disabled)}.",
                Explanation = allEnabled
                    ? "Die Windows-Firewall blockiert unerwünschte eingehende Verbindungen. Das ist eine der wichtigsten Grundschutzmaßnahmen."
                    : "Ohne aktive Firewall kann Schadsoftware offene Netzwerkports nutzen oder von außen erreicht werden.",
                RecommendedActions = allEnabled ? Array.Empty<string>() : new[]
                {
                    "Einstellungen → Datenschutz und Sicherheit → Windows-Sicherheit → Firewall- und Netzwerkschutz öffnen.",
                    $"Für das betroffene Netzwerkprofil die Firewall aktivieren ({string.Join(", ", disabled)})."
                },
                Limitations = "Diese Prüfung sieht nur den Ein/Aus-Status pro Profil, nicht die Regelkonfiguration.",
                Source = "Get-NetFirewallProfile"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("Firewall-Status konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static List<(string Name, bool Enabled)> ParseProfiles(string json)
    {
        var list = new List<(string, bool)>();
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Single object or array
            if (root.ValueKind == System.Text.Json.JsonValueKind.Object)
            {
                Add(list, root);
            }
            else if (root.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var item in root.EnumerateArray())
                    Add(list, item);
            }
        }
        catch { /* ignore parse errors -> Unknown */ }
        return list;

        static void Add(List<(string, bool)> l, System.Text.Json.JsonElement e)
        {
            string name = e.TryGetProperty("Name", out var n) ? n.GetString() ?? "?" : "?";
            bool enabled = e.TryGetProperty("Enabled", out var en) && en.ValueKind == System.Text.Json.JsonValueKind.True;
            l.Add((name, enabled));
        }
    }

    private static string NameOf(string name) => name switch
    {
        "Domain" => "Domänennetzwerk",
        "Private" => "Privates Netzwerk",
        "Public" => "Öffentliches Netzwerk",
        _ => name
    };

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.firewall",
        Title = "Windows-Firewall",
        Weight = CheckWeight.High,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Der Firewall-Status konnte nicht ausgelesen werden. Prüfe ihn manuell in den Windows-Sicherheitseinstellungen.",
        RecommendedActions = new[]
        {
            "Windows-Sicherheit → Firewall- und Netzwerkschutz öffnen und Status kontrollieren."
        },
        Source = "Get-NetFirewallProfile"
    };
}
