using System.Net.Http.Headers;
using System.Text;

namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Abstraktion über HTTP für Threat-Intel-Abfragen.
/// Trennung ermöglicht Tests ohne echtes Netzwerk.
/// </summary>
public interface IHttpTransport
{
    Task<string> PostFormAsync(string url, IEnumerable<KeyValuePair<string, string>> form,
        string? userAgent = null, CancellationToken ct = default);

    /// <summary>Rückwärtskompatible Variante (MalwareBazaar/URLhaus).</summary>
    Task<string> PostFormAsync(string url, IEnumerable<KeyValuePair<string, string>> fields, CancellationToken ct)
        => PostFormAsync(url, fields, null, ct);

    Task<string> PostJsonAsync(string url, string jsonBody, string? apiKey = null, CancellationToken ct = default);

    Task<string> GetAsync(string url, string? apiKey = null, string? authScheme = null, CancellationToken ct = default);
}

/// <summary>
/// Standard-Implementierung mit HttpClient.
/// </summary>
public sealed class HttpClientTransport : IHttpTransport, IDisposable
{
    private readonly HttpClient _client;

    public HttpClientTransport()
    {
        _client = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
    }

    public async Task<string> PostFormAsync(string url, IEnumerable<KeyValuePair<string, string>> fields,
        string? userAgent = null, CancellationToken ct = default)
    {
        using var content = new FormUrlEncodedContent(fields);
        using var response = await _client.PostAsync(url, content, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
    }

    public async Task<string> PostJsonAsync(string url, string jsonBody, string? apiKey = null,
        CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(jsonBody, Encoding.UTF8, "application/json")
        };
        if (apiKey is not null)
            request.Headers.Add("API-KEY", apiKey);

        using var response = await _client.SendAsync(request, ct).ConfigureAwait(false);
        return await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
    }

    public async Task<string> GetAsync(string url, string? apiKey = null, string? authScheme = null,
        CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (apiKey is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue(authScheme ?? "Bearer", apiKey);

        using var response = await _client.SendAsync(request, ct).ConfigureAwait(false);
        return await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
    }

    public void Dispose() => _client.Dispose();
}
