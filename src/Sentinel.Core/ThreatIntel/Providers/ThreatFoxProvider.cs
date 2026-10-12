using System.Diagnostics;
using System.Text.Json;

namespace Sentinel.Core.ThreatIntel.Providers;

/// <summary>
/// ThreatFox (abuse.ch): IOCs aller Art (Domains, IPs, URLs, Hashes), kein Key nötig.
/// API: POST https://threatfox-api.abuse.ch/api/v1/ { query: 'search_ioc', search_term }
/// </summary>
public sealed class ThreatFoxProvider : IThreatProvider
{
    private const string Endpoint = "https://threatfox-api.abuse.ch/api/v1/";

    private readonly IHttpTransport _transport;

    public ThreatFoxProvider(IHttpTransport transport) => _transport = transport;

    public string Id => "threatfox";
    public string Name => "ThreatFox (abuse.ch)";
    public string Description => "IOC-Datenbank: Domains, IPs, URLs und Hashes bekannter Malware. Kein API-Key nötig.";
    public bool RequiresApiKey => false;
    public string InfoUrl => "https://threatfox.abuse.ch/";
    public IReadOnlyList<ThreatKind> SupportedKinds { get; } =
        new[] { ThreatKind.Url, ThreatKind.IpAddress, ThreatKind.Domain, ThreatKind.FileHash };

    public async Task<ProviderOutcome> QueryAsync(ThreatQuery query, string? apiKey, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            string body = JsonSerializer.Serialize(new { query = "search_ioc", search_term = query.Value });
            string response = await _transport.PostJsonAsync(Endpoint, body, ct: ct).ConfigureAwait(false);

            using var doc = JsonDocument.Parse(response);
            var root = doc.RootElement;

            // query_status: "ok" = etwas gefunden, "no_result" = nichts gefunden, "no_search_input" etc.
            string status = root.TryGetProperty("query_status", out var qs) ? qs.GetString() ?? "" : "";

            if (status == "no_result")
                return Found(query.Value, false, sw.Elapsed);

            if (status != "ok")
                return Failed(query.Value, sw.Elapsed, $"Status: {status}");

            int count = 0;
            string? malware = null;
            string? threatType = null;
            var reporters = new List<string>();

            if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
            {
                count = data.GetArrayLength();
                foreach (var entry in data.EnumerateArray())
                {
                    malware ??= entry.TryGetProperty("malware_printable", out var m) ? m.GetString() : null;
                    threatType ??= entry.TryGetProperty("threat_type", out var t) ? t.GetString() : null;
                    if (entry.TryGetProperty("reporter", out var r) && r.GetString() is { Length: > 0 } rn
                        && !reporters.Contains(rn))
                        reporters.Add(rn);
                }
            }

            bool isThreat = count > 0;
            string details = isThreat
                ? $"{malware ?? "unbekannt"} · {threatType ?? "?"}"
                : "nicht gelistet";

            return new ProviderOutcome
            {
                ProviderId = Id,
                ProviderName = Name,
                IsThreat = isThreat,
                QuerySucceeded = true,
                Category = threatType,
                Details = details,
                Latency = sw.Elapsed,
                DetectionCount = count
            };
        }
        catch (Exception ex)
        {
            return Failed(query.Value, sw.Elapsed, ex.Message);
        }
    }

    private static ProviderOutcome Found(string value, bool isThreat, TimeSpan latency) => new()
    {
        ProviderId = "threatfox", ProviderName = "ThreatFox (abuse.ch)",
        IsThreat = isThreat, QuerySucceeded = true, Latency = latency,
        Details = isThreat ? "gelistet" : "nicht gelistet"
    };

    private static ProviderOutcome Failed(string value, TimeSpan latency, string error) => new()
    {
        ProviderId = "threatfox", ProviderName = "ThreatFox (abuse.ch)",
        IsThreat = false, QuerySucceeded = false, Error = error, Latency = latency
    };
}
