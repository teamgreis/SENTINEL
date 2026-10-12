using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft, ob das aktive WLAN verschlüsselt ist (WPA2/WPA3).
/// Read-only über netsh.
/// </summary>
public sealed class WifiEncryptionCheck : ICheck
{
    public string Id => "network.wifiencryption";
    public string Title => "WLAN-Verschlüsselung";
    public CheckWeight Weight => CheckWeight.High;
    public string Description => "Prüft die Verschlüsselung des aktuellen WLANs.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$p = Get-NetConnectionProfile | Where-Object { $_.IPv4Connectivity -ne 'Disconnected' } | Select-Object -First 1; " +
                "if ($p) { netsh wlan show interfaces name=$($p.Name) | Select-String -Pattern 'Authentifizierung|Authentication|Verschlüsselung|Cipher|SSID' } else { 'kein wlan' }",
                ct).ConfigureAwait(false);

            string combined = output + "\n" + error;

            if (combined.Contains("kein wlan") || combined.Trim().Length == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Info,
                    Detail = "Kein aktives WLAN erkannt (vermutlich LAN-Verbindung).",
                    Explanation = "Bei einer kabelgebundenen Verbindung ist dieser Check nicht relevant.",
                    Source = "netsh wlan show interfaces"
                };
            }

            string lower = combined.ToLowerInvariant();
            string auth = Extract(lower, "authentifizierung", "authentication");
            string cipher = Extract(lower, "verschlüsselung", "cipher");

            bool isOpen = lower.Contains("offen") || lower.Contains("open") ||
                          (auth.Contains("offen") || auth.Contains("open"));

            bool isWpa3 = lower.Contains("wpa3");
            bool isWpa2 = lower.Contains("wpa2") || lower.Contains("ccmp") || lower.Contains("aes");
            bool isWep = lower.Contains("wep");

            if (isOpen)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Fail,
                    Detail = "Das WLAN ist offen (unverschlüsselt)!",
                    Explanation = "Jeder in Reichweite kann den kompletten Datenverkehr mitlesen – einschließlich Passwörter und E-Mails. Auch in Cafés und Hotels nie ohne VPN verbinden.",
                    RecommendedActions = new[]
                    {
                        "Sofort trennen und ein anderes Netzwerk nutzen.",
                        "Wenn es dein eigenes WLAN ist: Router-Einstellungen → WPA2/WPA3 aktivieren."
                    },
                    Source = "netsh wlan show interfaces"
                };
            }

            if (isWep)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Fail,
                    Detail = "Das WLAN nutzt WEP – veraltet und in Minuten knackbar.",
                    Explanation = "WEP gilt seit 2004 als gebrochen. Ein Angreifer kann den Schlüssel mit frei verfügbaren Tools in Minuten berechnen.",
                    RecommendedActions = new[]
                    {
                        "Router auf WPA2-PSK oder besser WPA3 umstellen.",
                        "Alle Geräte mit dem neuen Schlüssel verbinden."
                    },
                    Source = "netsh wlan show interfaces"
                };
            }

            if (isWpa3 || isWpa2)
            {
                string proto = isWpa3 ? "WPA3" : "WPA2";
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = $"WLAN ist mit {proto} verschlüsselt.",
                    Explanation = "Moderne Verschlüsselung schützt den Funkverkehr. WPA3 bietet zusätzlichen Schutz gegen Offline-Wörterbuchangriffe.",
                    Source = "netsh wlan show interfaces"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Unknown,
                Detail = "Verschlüsselungstyp nicht bestimmbar.",
                Explanation = $"Gefundene Angaben: Auth={auth}, Cipher={cipher}. Prüfe in den WLAN-Einstellungen den Sicherheitstyp.",
                Source = "netsh wlan show interfaces"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static string Extract(string text, params string[] keys)
    {
        foreach (var line in text.Split('\n'))
        {
            foreach (var key in keys)
            {
                int idx = line.IndexOf(key, StringComparison.Ordinal);
                if (idx >= 0)
                {
                    var rest = line[(idx + key.Length)..].TrimStart(':', ' ');
                    if (rest.Length > 0) return rest.Trim();
                }
            }
        }
        return "";
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "network.wifiencryption", Title = "WLAN-Verschlüsselung", Weight = CheckWeight.High,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe in den WLAN-Einstellungen den Sicherheitstyp des verbundenen Netzwerks.",
        Source = "netsh wlan show interfaces"
    };
}
