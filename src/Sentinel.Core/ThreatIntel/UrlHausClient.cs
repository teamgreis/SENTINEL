using System.Text.Json;

namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Client für URLhaus (abuse.ch) – prüft URLs gegen eine Datenbank
/// bekannter bösartiger Links. Kostenlos, kein API-Key.
/// Sendet ausschließlich die geprüfte URL – nie weitere Daten.
/// </summary>
public sealed class UrlHausClient
{
    public const string Endpoint = "https://urlhaus-api.abuse.ch/v1/url/";

    private readonly IHttpTransport _transport;

    public UrlHausClient(IHttpTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    public async Task<ThreatIntelResult> LookupUrlAsync(string url, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(url))
            return ThreatIntelResult.Failed(url ?? "", "Keine URL angegeben.", "URLhaus");

        try
        {
            var json = await _transport.PostFormAsync(Endpoint, new[]
            {
                new KeyValuePair<string, string>("url", url.Trim())
            }, ct).ConfigureAwait(false);

            return UrlHausParser.Parse(json, url);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return ThreatIntelResult.Failed(url, ex.Message, "URLhaus");
        }
    }
}

/// <summary>Parst URLhaus-Antworten. Reine Logik – testbar ohne Netz.</summary>
public static class UrlHausParser
{
    public static ThreatIntelResult Parse(string json, string query)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string status = root.TryGetProperty("query_status", out var s) ? s.GetString() ?? "" : "";

            // "ok" = URL ist gelistet; "no_results" = nichts gefunden
            if (status == "no_results")
                return ThreatIntelResult.NotListed(query, "URLhaus");

            if (status != "ok")
                return ThreatIntelResult.Failed(query, $"Unerwarteter Status: {status}", "URLhaus");

            string? urlStatus = root.TryGetProperty("url_status", out var us) ? us.GetString() : null;
            string? threat = root.TryGetProperty("threat", out var t) ? t.GetString() : null;

            string signature = threat ?? "Bösartiger Link";

            return ThreatIntelResult.Listed(query, signature, null, urlStatus, 1, "URLhaus");
        }
        catch (Exception ex)
        {
            return ThreatIntelResult.Failed(query, $"Antwort nicht lesbar: {ex.Message}", "URLhaus");
        }
    }
}
