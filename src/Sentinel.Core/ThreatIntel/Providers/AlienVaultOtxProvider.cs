using System.Diagnostics;
using System.Text.Json;

namespace Sentinel.Core.ThreatIntel.Providers;

/// <summary>
/// AlienVault OTX (Open Threat Exchange): Pulse-Datenbank für alle IOC-Arten.
/// Kostenloser Key, community-gespeist.
/// </summary>
public sealed class AlienVaultOtxProvider : IThreatProvider
{
    private const string Base = "https://otx.alienvault.com/api/v1/indicators/";

    private readonly IHttpTransport _transport;

    public AlienVaultOtxProvider(IHttpTransport transport) => _transport = transport;

    public string Id => "otx";
    public string Name => "AlienVault OTX";
    public string Description => "Community-Bedrohungsdatenbank (Pulses) für IPs, Domains, URLs, Hashes. Kostenloser Key.";
    public bool RequiresApiKey => true;
    public string InfoUrl => "https://otx.alienvault.com/";
    public IReadOnlyList<ThreatKind> SupportedKinds { get; } =
        new[] { ThreatKind.IpAddress, ThreatKind.Domain, ThreatKind.Url, ThreatKind.FileHash };

    public async Task<ProviderOutcome> QueryAsync(ThreatQuery query, string? apiKey, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();

        if (string.IsNullOrWhiteSpace(apiKey))
            return Failed(sw.Elapsed, "Kein API-Key hinterlegt.");

        try
        {
            string section = query.Kind switch
            {
                ThreatKind.IpAddress => "IPv4",
                ThreatKind.Domain => "domain",
                ThreatKind.Url => "url",
                ThreatKind.FileHash => "file",
                _ => throw new NotSupportedException()
            };

            string url = $"{Base}{section}/{query.Value}/general";

            string response = await _transport.GetAsync(url, apiKey, "Bearer", ct).ConfigureAwait(false);

            using var doc = JsonDocument.Parse(response);
            var root = doc.RootElement;

            // pulse_info.pulse_count
            int pulseCount = 0;
            if (root.TryGetProperty("pulse_info", out var pulseInfo) &&
                pulseInfo.TryGetProperty("count", out var c))
                pulseCount = c.GetInt32();

            // validation: Liste der Scanner-Ergebnisse
            int flaggedValidations = 0;
            if (root.TryGetProperty("validation", out var validation))
            {
                foreach (var v in validation.EnumerateArray())
                    if (v.TryGetProperty("detected", out var d) && d.GetBoolean())
                        flaggedValidations++;
            }

            bool isThreat = pulseCount > 0 || flaggedValidations > 0;

            return new ProviderOutcome
            {
                ProviderId = Id, ProviderName = Name,
                IsThreat = isThreat, QuerySucceeded = true,
                Category = isThreat ? "in pulses gelistet" : "clean",
                Details = $"{pulseCount} Pulse(s), {flaggedValidations} Scanner-Treffer",
                Latency = sw.Elapsed,
                DetectionCount = pulseCount
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
