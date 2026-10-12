using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft DNS-Server-Konfiguration auf bekannte unsichere Anbieter.
/// Read-only über Get-DnsClientServerAddress.
/// </summary>
public sealed class DnsServerCheck : ICheck
{
    public string Id => "network.dnsservers";
    public string Title => "DNS-Server";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft die konfigurierten DNS-Server auf bekannte Anbieter.";

    // Öffentliche DNS-Anbieter mit Malware-/Phishing-Filter
    private static readonly Dictionary<string, string> KnownDns = new(StringComparer.OrdinalIgnoreCase)
    {
        ["1.1.1.1"] = "Cloudflare (gefiltert)",
        ["1.0.0.1"] = "Cloudflare (gefiltert)",
        ["8.8.8.8"] = "Google",
        ["8.8.4.4"] = "Google",
        ["9.9.9.9"] = "Quad9 (gefiltert)",
        ["149.112.112.112"] = "Quad9 (gefiltert)",
        ["94.140.14.14"] = "AdGuard (gefiltert)",
        ["94.140.15.15"] = "AdGuard (gefiltert)",
        ["208.67.222.222"] = "OpenDNS/Cisco (gefiltert)",
        ["208.67.220.220"] = "OpenDNS/Cisco (gefiltert)"
    };

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | ForEach-Object { $_.ServerAddresses -join ',' }) -join ';'",
                ct).ConfigureAwait(false);

            string combined = (output + ";" + error).Trim();

            if (combined.Length == 0 || combined == ";")
                return Unknown("Keine DNS-Server konfiguriert.");

            var servers = combined.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim())
                .Where(s => s.Length > 0)
                .Distinct()
                .ToList();

            var known = servers.Where(KnownDns.ContainsKey).ToList();
            var unknown = servers.Where(s => !KnownDns.ContainsKey(s)).ToList();

            string knownText = known.Count > 0
                ? string.Join(", ", known.Select(s => $"{s} ({KnownDns[s]})"))
                : "keine bekannten Anbieter";

            if (known.Count > 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = $"Bekannte DNS-Anbieter in Nutzung: {knownText}.",
                    Explanation = "Diese Anbieter betreiben Malware- und Phishing-Filter. Sie sehen außerdem alle deine Domain-Anfragen.",
                    Source = "Get-DnsClientServerAddress",
                    Limitations = "DNS-Anfragen sind für den Anbieter sichtbar – ein Kompromiss zwischen Schutz und Privatsphäre."
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Info,
                Detail = $"Konfigurierte DNS-Server: {string.Join(", ", servers)} (keine bekannten gefilterten Anbieter).",
                Explanation = "Das sind meist Router-Adressen. Für gefiltertes DNS kannst du z. B. 1.1.1.2/1.0.0.2 (Cloudflare Malware-Block) oder 9.9.9.9 (Quad9) eintragen.",
                Source = "Get-DnsClientServerAddress"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "network.dnsservers", Title = "DNS-Server", Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe in den Adaptereinstellungen, welche DNS-Server konfiguriert sind.",
        Source = "Get-DnsClientServerAddress"
    };
}
