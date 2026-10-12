using Sentinel.Core.ThreatIntel;
using Sentinel.Core.ThreatIntel.Providers;
using Xunit;

namespace Sentinel.Tests;

public class ThreatAggregatorTests
{
    private static ThreatAggregator CreateAggregator()
    {
        var providers = new IThreatProvider[]
        {
            new ThreatFoxProvider(new FakeTransport("""{"query_status":"no_result"}""")),
            new VirusTotalProvider(new FakeTransport("""{"data":{"attributes":{"last_analysis_stats":{"malicious":1,"suspicious":0,"harmless":70}}}}""")),
            new SafeBrowsingProvider(new FakeTransport("""{"matches":[{"threatType":"MALWARE"}]}""")),
            new AlienVaultOtxProvider(new FakeTransport("""{"pulse_info":{"count":5},"validation":[]}"""))
        };

        return new ThreatAggregator(providers,
            new MemoryResultCache(),
            new PerProviderRateLimiter(new Dictionary<string, int> { ["virustotal"] = 4 }));
    }

    [Fact]
    public async Task MultipleProviders_Aggregate()
    {
        var aggregator = CreateAggregator();
        Func<string, string?> keyProvider = id => id == "virustotal" || id == "safebrowsing" || id == "otx" ? "key" : null;

        var verdict = await aggregator.CheckAsync(
            new ThreatQuery(ThreatKind.Url, "http://test.example.com"), keyProvider);

        // 3 Provider haben Keys und unterstützen URLs (ThreatFox braucht keinen)
        Assert.Equal(4, verdict.ProvidersQueried);

        // Safe Browsing meldet MALWARE, OTX 5 Pulses, VirusTotal 1 malicious
        // ThreatFox: no_result
        Assert.True(verdict.ProvidersFlagged >= 3);
        Assert.True(verdict.AnyFlagged);
        Assert.True(verdict.Confidence > 50);
    }

    [Fact]
    public async Task WithoutKeys_OnlyFreeProviders()
    {
        var aggregator = CreateAggregator();
        Func<string, string?> keyProvider = _ => null;

        var verdict = await aggregator.CheckAsync(
            new ThreatQuery(ThreatKind.Url, "http://test.example.com"), keyProvider);

        // Nur ThreatFox braucht keinen Key
        Assert.Equal(1, verdict.ProvidersQueried);
        Assert.False(verdict.AnyFlagged); // no_result
    }

    [Fact]
    public async Task Cache_AvoidsDuplicateQueries()
    {
        var callCount = 0;
        var transport = new CountingTransport(() => Interlocked.Increment(ref callCount));
        var provider = new ThreatFoxProvider(transport);
        var cache = new MemoryResultCache();
        var aggregator = new ThreatAggregator(new IThreatProvider[] { provider }, cache);

        var query = new ThreatQuery(ThreatKind.Domain, "example.com");
        Func<string, string?> keyProvider = _ => null;

        await aggregator.CheckAsync(query, keyProvider);
        await aggregator.CheckAsync(query, keyProvider); // sollte aus Cache kommen

        Assert.Equal(1, callCount); // nur eine echte Abfrage
    }

    [Fact]
    public async Task RateLimiter_BlocksAfterLimit()
    {
        var callCount = 0;
        var transport = new CountingTransport(() => Interlocked.Increment(ref callCount));
        var limiter = new PerProviderRateLimiter(new Dictionary<string, int> { ["virustotal"] = 2 });
        var aggregator = new ThreatAggregator(
            new IThreatProvider[] { new VirusTotalProvider(transport) }, null, limiter);

        Func<string, string?> keyProvider = id => id == "virustotal" ? "key" : null;
        var query = new ThreatQuery(ThreatKind.Url, "http://example.com");

        await aggregator.CheckAsync(query, keyProvider); // 1
        await aggregator.CheckAsync(query, keyProvider); // 2
        var verdict = await aggregator.CheckAsync(query, keyProvider); // 3 → Rate-Limit

        Assert.Equal(2, callCount); // nur 2 echte Abfragen
        Assert.True(verdict.Outcomes.Any(o => o.Error?.Contains("Rate-Limit") == true));
    }

    [Fact]
    public async Task ProviderFailure_DoesNotBlockOthers()
    {
        var providers = new IThreatProvider[]
        {
            new FailingProvider("failing"),
            new ThreatFoxProvider(new FakeTransport("""{"query_status":"no_result"}"""))
        };
        var aggregator = new ThreatAggregator(providers);

        var verdict = await aggregator.CheckAsync(
            new ThreatQuery(ThreatKind.Url, "http://test.example.com"), _ => null);

        Assert.Equal(2, verdict.ProvidersQueried);
        Assert.True(verdict.Outcomes.Any(o => o.ProviderId == "failing" && !o.QuerySucceeded));
        Assert.True(verdict.Outcomes.Any(o => o.ProviderId == "threatfox" && o.QuerySucceeded));
    }

    [Fact]
    public async Task Confidence_CalculatedCorrectly()
    {
        var providers = new IThreatProvider[]
        {
            new SafeBrowsingProvider(new FakeTransport("""{"matches":[{"threatType":"MALWARE"}]}""")),
            new SafeBrowsingProvider2("safebrowsing-clean", clean: true)
        };
        var aggregator = new ThreatAggregator(providers);

        var verdict = await aggregator.CheckAsync(
            new ThreatQuery(ThreatKind.Url, "http://test.example.com"), _ => "key");

        Assert.Equal(2, verdict.ProvidersQueried);
        Assert.Equal(1, verdict.ProvidersFlagged);
        Assert.Equal(50, verdict.Confidence); // 1 von 2
    }

    // ---------- Fakes ----------

    private sealed class FakeTransport(string response) : IHttpTransport
    {
        public Task<string> PostFormAsync(string url, IEnumerable<KeyValuePair<string, string>> form,
            string? userAgent = null, CancellationToken ct = default) => Task.FromResult(response);

        public Task<string> PostJsonAsync(string url, string jsonBody, string? apiKey = null,
            CancellationToken ct = default) => Task.FromResult(response);

        public Task<string> GetAsync(string url, string? apiKey = null, string? authScheme = null,
            CancellationToken ct = default) => Task.FromResult(response);
    }

    private sealed class CountingTransport : IHttpTransport
    {
        private readonly Func<int> _increment;
        public CountingTransport(Func<int> increment) => _increment = increment;

        public Task<string> PostJsonAsync(string url, string jsonBody, string? apiKey = null,
            CancellationToken ct = default)
        {
            _increment();
            return Task.FromResult("""{"query_status":"no_result"}""");
        }

        public Task<string> PostFormAsync(string url, IEnumerable<KeyValuePair<string, string>> form,
            string? userAgent = null, CancellationToken ct = default) => Task.FromResult("");

        public Task<string> GetAsync(string url, string? apiKey = null, string? authScheme = null,
            CancellationToken ct = default)
        {
            _increment();
            return Task.FromResult("""{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":70}}}}""");
        }
    }

    private sealed class FailingProvider(string id) : IThreatProvider
    {
        public string Id => id;
        public string Name => $"Failing {id}";
        public string Description => "Always fails";
        public bool RequiresApiKey => false;
        public string InfoUrl => "http://localhost";
        public IReadOnlyList<ThreatKind> SupportedKinds { get; } = new[] { ThreatKind.Url };

        public Task<ProviderOutcome> QueryAsync(ThreatQuery query, string? apiKey, CancellationToken ct = default)
        {
            throw new InvalidOperationException("Provider ist ausgefallen");
        }
    }

    private sealed class SafeBrowsingProvider2(string id, bool clean) : IThreatProvider
    {
        public string Id => id;
        public string Name => $"SB {id}";
        public string Description => "Test";
        public bool RequiresApiKey => true;
        public string InfoUrl => "http://localhost";
        public IReadOnlyList<ThreatKind> SupportedKinds { get; } = new[] { ThreatKind.Url };

        public Task<ProviderOutcome> QueryAsync(ThreatQuery query, string? apiKey, CancellationToken ct = default)
        {
            return Task.FromResult(new ProviderOutcome
            {
                ProviderId = id, ProviderName = Name,
                IsThreat = !clean, QuerySucceeded = true
            });
        }
    }
}
