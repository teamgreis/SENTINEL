using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core.ThreatIntel.Providers;

namespace Sentinel.Core.ThreatIntel;

/// <summary>Erstellt alle verfügbaren Provider. Neue Datenbank = hier eine Zeile.</summary>
public static class ProviderFactory
{
    public static IReadOnlyList<IThreatProvider> CreateAll(IHttpTransport transport) => new IThreatProvider[]
    {
        new ThreatFoxProvider(transport),
        new VirusTotalProvider(transport),
        new SafeBrowsingProvider(transport),
        new AlienVaultOtxProvider(transport)
    };
}

/// <summary>
/// Erstellt einen voll konfigurierten Aggregator aus einer Key-Verwaltung.
/// </summary>
public static class ThreatIntelFactory
{
    public static ThreatAggregator Create(IHttpTransport transport, ApiKeyStore store,
        IResultCache? cache = null, IRateLimiter? rateLimiter = null)
    {
        var providers = ProviderFactory.CreateAll(transport);
        return new ThreatAggregator(providers, cache, rateLimiter);
    }
}

/// <summary>
/// Speichert API-Keys und Aktivierungsstatus der Datenbanken.
/// Keys liegen in %LOCALAPPDATA%\SENTINEL\apikeys.json (Klartext, aber nur lokal,
/// nie übertragen außer an die jeweilige Datenbank).
/// </summary>
public sealed class ApiKeyStore
{
    private readonly string _path;
    private Dictionary<string, ProviderConfig> _configs = new();

    [JsonConstructor]
    private ApiKeyStore() : this("apikeys.json") { }

    public ApiKeyStore(string path)
    {
        _path = path;
        Load();
    }

    public string? GetKey(string providerId) =>
        _configs.TryGetValue(providerId, out var c) ? c.ApiKey : null;

    public bool IsEnabled(string providerId) =>
        !_configs.TryGetValue(providerId, out var c) || c.Enabled;

    public void SetKey(string providerId, string? key)
    {
        var c = GetOrCreate(providerId);
        c.ApiKey = string.IsNullOrWhiteSpace(key) ? null : key.Trim();
        Save();
    }

    public void SetEnabled(string providerId, bool enabled)
    {
        var c = GetOrCreate(providerId);
        c.Enabled = enabled;
        Save();
    }

    /// <summary>Alle konfigurierten Provider-IDs.</summary>
    public IEnumerable<string> ConfiguredIds => _configs.Keys;

    public void Save()
    {
        var dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(_path, JsonSerializer.Serialize(this, WriteOptions));
    }

    private void Load()
    {
        if (!File.Exists(_path)) return;
        try
        {
            var data = JsonSerializer.Deserialize<StoredData>(File.ReadAllText(_path), WriteOptions);
            _configs = data?.Providers ?? new Dictionary<string, ProviderConfig>();
        }
        catch
        {
            _configs = new Dictionary<string, ProviderConfig>();
        }
    }

    private ProviderConfig GetOrCreate(string providerId)
    {
        if (!_configs.TryGetValue(providerId, out var c))
        {
            c = new ProviderConfig();
            _configs[providerId] = c;
        }
        return c;
    }

    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public sealed class ProviderConfig
    {
        [JsonPropertyName("apiKey")]
        public string? ApiKey { get; set; }

        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;
    }

    private sealed class StoredData
    {
        [JsonPropertyName("providers")]
        public Dictionary<string, ProviderConfig> Providers { get; set; } = new();
    }
}
