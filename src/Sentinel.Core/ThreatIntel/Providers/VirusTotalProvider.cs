using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Sentinel.Core.ThreatIntel.Providers;

/// <summary>
/// VirusTotal: URLs und Datei-Hashes. Kostenloser API-Key nötig (4 Abfragen/Minute).
/// </summary>
public sealed class VirusTotalProvider : IThreatProvider
{
    private const string UrlBase = "https://www.virustotal.com/api/v3/urls/";
    private const string FileBase = "https://www.virustotal.com/api/v3/files/";

    private readonly IHttpTransport _transport;

    public VirusTotalProvider(IHttpTransport transport) => _transport = transport;

    public string Id => "virustotal";
    public string Name => "VirusTotal";
    public string Description => "70+ Virenscanner gegen URLs und Datei-Hashes. API-Key nötig (kostenlos, 4 Abfragen/Minute).";
    public bool RequiresApiKey => true;
    public string InfoUrl => "https://www.virustotal.com/gui/my-apikey";
    public IReadOnlyList<ThreatKind> SupportedKinds { get; } =
        new[] { ThreatKind.Url, ThreatKind.FileHash };

    public async Task<ProviderOutcome> QueryAsync(ThreatQuery query, string? apiKey, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();

        if (string.IsNullOrWhiteSpace(apiKey))
            return Failed(sw.Elapsed, "Kein API-Key hinterlegt.");

        try
        {
            string url = query.Kind switch
            {
                ThreatKind.Url => UrlBase + UrlId(query.Value),
                ThreatKind.FileHash => FileBase + query.Value,
                _ => throw new NotSupportedException($"VirusTotal unterstützt {query.Kind} nicht.")
            };

            string response = await _transport.GetAsync(url, apiKey, "x-apikey", ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(response);
            var root = doc.RootElement;

            if (!root.TryGetProperty("data", out var data))
                return Failed(sw.Elapsed, "Unerwartete Antwort.");

            // Letzte Analyse: data.attributes.last_analysis_stats
            int malicious = 0, suspicious = 0, harmless = 0;
            if (data.TryGetProperty("attributes", out var attrs) &&
                attrs.TryGetProperty("last_analysis_stats", out var stats))
            {
                if (stats.TryGetProperty("malicious", out var m)) malicious = m.GetInt32();
                if (stats.TryGetProperty("suspicious", out var s)) suspicious = s.GetInt32();
                if (stats.TryGetProperty("harmless", out var h)) harmless = h.GetInt32();
            }

            bool isThreat = malicious > 0 || suspicious > 0;

            return new ProviderOutcome
            {
                ProviderId = Id, ProviderName = Name,
                IsThreat = isThreat, QuerySucceeded = true,
                Category = isThreat ? "malicious" : "clean",
                Details = $"{malicious} bösartig, {suspicious} verdächtig, {harmless} harmlos",
                Latency = sw.Elapsed,
                DetectionCount = malicious + suspicious
            };
        }
        catch (Exception ex)
        {
            return Failed(sw.Elapsed, ex.Message);
        }
    }

    /// <summary>VirusTotal erwartet die URL ohne Schema, base64-codiert ohne Padding.</summary>
    private static string UrlId(string url)
    {
        string normalized = url.Contains("://") ? url : "http://" + url;
        string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(normalized));
        return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private ProviderOutcome Failed(TimeSpan latency, string error) => new()
    {
        ProviderId = Id, ProviderName = Name,
        IsThreat = false, QuerySucceeded = false, Error = error, Latency = latency
    };
}
