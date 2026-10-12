using System.Diagnostics;
using System.Text.Json;

namespace Sentinel.Core.ThreatIntel.Providers;

/// <summary>
/// Google Safe Browsing v4 (Lookup API): Phishing/Malware/Schadsoftware-Listen.
/// Kostenloser API-Key (Google Cloud Console), 10.000 Abfragen/Tag.
/// </summary>
public sealed class SafeBrowsingProvider : IThreatProvider
{
    private const string Endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

    private readonly IHttpTransport _transport;

    public SafeBrowsingProvider(IHttpTransport transport) => _transport = transport;

    public string Id => "safebrowsing";
    public string Name => "Google Safe Browsing";
    public string Description => "Phishing-/Malware-Listen von Google (Chrome nutzt dieselben Daten). API-Key nötig.";
    public bool RequiresApiKey => true;
    public string InfoUrl => "https://console.cloud.google.com/apis/credentials";
    public IReadOnlyList<ThreatKind> SupportedKinds { get; } = new[] { ThreatKind.Url };

    public async Task<ProviderOutcome> QueryAsync(ThreatQuery query, string? apiKey, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();

        if (string.IsNullOrWhiteSpace(apiKey))
            return Failed(sw.Elapsed, "Kein API-Key hinterlegt.");

        if (query.Kind != ThreatKind.Url)
            return Failed(sw.Elapsed, "Safe Browsing prüft nur URLs.");

        try
        {
            string normalized = query.Value.Contains("://") ? query.Value : "http://" + query.Value;
            var requestBody = new
            {
                client = new { clientId = "sentinel", clientVersion = "1.0" },
                threatInfo = new
                {
                    threatTypes = new[] { "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION" },
                    platformTypes = new[] { "ANY_PLATFORM" },
                    threatEntryTypes = new[] { "URL" },
                    threatEntries = new[] { new { url = normalized } }
                }
            };

            string json = JsonSerializer.Serialize(requestBody);
            string response = await _transport.PostJsonAsync(
                $"{Endpoint}?key={apiKey}", json, ct: ct).ConfigureAwait(false);

            using var doc = JsonDocument.Parse(response);
            bool isThreat = doc.RootElement.TryGetProperty("matches", out var matches)
                && matches.ValueKind == JsonValueKind.Array
                && matches.GetArrayLength() > 0;

            string details = "keine Treffer";
            if (isThreat)
            {
                var types = new List<string>();
                foreach (var m in matches.EnumerateArray())
                    if (m.TryGetProperty("threatType", out var t))
                        types.Add(t.GetString() ?? "?");
                details = string.Join(", ", types.Distinct());
            }

            return new ProviderOutcome
            {
                ProviderId = Id, ProviderName = Name,
                IsThreat = isThreat, QuerySucceeded = true,
                Category = isThreat ? details : null,
                Details = details, Latency = sw.Elapsed,
                DetectionCount = isThreat ? matches.GetArrayLength() : 0
            };
        }
        catch (Exception ex)
        {
            return Failed(sw.Elapsed, ex.Message);
        }
    }

    private ProviderOutcome Failed(TimeSpan latency, string error) => new()
    {
        ProviderId = Id, ProviderName = Name,
        IsThreat = false, QuerySucceeded = false, Error = error, Latency = latency
    };
}
