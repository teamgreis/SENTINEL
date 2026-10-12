using System.Text.Json;
using Sentinel.Core.ThreatIntel;
using Sentinel.Core.ThreatIntel.Providers;
using Xunit;

namespace Sentinel.Tests;

public class ProviderTests
{
    // ---------- ThreatFox ----------

    [Fact]
    public async Task ThreatFox_DetectsKnownIoc()
    {
        // bösartige Domain (Beispiel aus der Doku)
        string json = """{"query_status":"ok","data":[{"malware_printable":"Cobalt Strike","threat_type":"botnet_c2","reporter":"test"}]}""";
        var transport = new FakeTransport(json);
        var provider = new ThreatFoxProvider(transport);

        var result = await provider.QueryAsync(new ThreatQuery(ThreatKind.Domain, "evil.example.com"), null);

        Assert.True(result.QuerySucceeded);
        Assert.True(result.IsThreat);
        Assert.Equal("botnet_c2", result.Category);
        Assert.Contains("Cobalt Strike", result.Details);
    }

    [Fact]
    public async Task ThreatFox_CleanDomain()
    {
        string json = """{"query_status":"no_result"}""";
        var transport = new FakeTransport(json);
        var provider = new ThreatFoxProvider(transport);

        var result = await provider.QueryAsync(new ThreatQuery(ThreatKind.Domain, "example.com"), null);

        Assert.True(result.QuerySucceeded);
        Assert.False(result.IsThreat);
    }

    // ---------- VirusTotal ----------

    [Fact]
    public async Task VirusTotal_DetectsMaliciousUrl()
    {
        string json = """{"data":{"attributes":{"last_analysis_stats":{"malicious":42,"suspicious":2,"harmless":30}}}}""";
        var transport = new FakeTransport(json);
        var provider = new VirusTotalProvider(transport);

        var result = await provider.QueryAsync(
            new ThreatQuery(ThreatKind.Url, "http://evil.example.com"), "test-key");

        Assert.True(result.QuerySucceeded);
        Assert.True(result.IsThreat);
        Assert.Equal(44, result.DetectionCount);
    }

    [Fact]
    public async Task VirusTotal_CleanUrl()
    {
        string json = """{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":72}}}}""";
        var transport = new FakeTransport(json);
        var provider = new VirusTotalProvider(transport);

        var result = await provider.QueryAsync(
            new ThreatQuery(ThreatKind.Url, "https://example.com"), "test-key");

        Assert.True(result.QuerySucceeded);
        Assert.False(result.IsThreat);
    }

    [Fact]
    public async Task VirusTotal_RequiresKey()
    {
        var transport = new FakeTransport("");
        var provider = new VirusTotalProvider(transport);

        var result = await provider.QueryAsync(
            new ThreatQuery(ThreatKind.Url, "https://example.com"), null);

        Assert.False(result.QuerySucceeded);
        Assert.Contains("Kein API-Key", result.Error);
    }

    [Fact]
    public void VirusTotal_UrlId_MatchesGoogleAlgorithm()
    {
        // http://example.com → base64: aHR0cDovL2V4YW1wbGUuY29t
        string url = "http://example.com";
        string expected = "aHR0cDovL2V4YW1wbGUuY29t";

        var transport = new FakeTransport("");
        var provider = new VirusTotalProvider(transport);
        string actual = provider.GetType()
            .GetMethod("UrlId", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
            .Invoke(null, new object[] { url }) as string;

        Assert.Equal(expected, actual);
    }

    // ---------- Safe Browsing ----------

    [Fact]
    public async Task SafeBrowsing_DetectsMalware()
    {
        string json = """{"matches":[{"threatType":"MALWARE","platformType":"ANY_PLATFORM"}]}""";
        var transport = new FakeTransport(json);
        var provider = new SafeBrowsingProvider(transport);

        var result = await provider.QueryAsync(
            new ThreatQuery(ThreatKind.Url, "http://malware.example.com"), "test-key");

        Assert.True(result.QuerySucceeded);
        Assert.True(result.IsThreat);
        Assert.Contains("MALWARE", result.Details);
    }

    [Fact]
    public async Task SafeBrowsing_CleanUrl()
    {
        string json = "{}";
        var transport = new FakeTransport(json);
        var provider = new SafeBrowsingProvider(transport);

        var result = await provider.QueryAsync(
            new ThreatQuery(ThreatKind.Url, "https://example.com"), "test-key");

        Assert.True(result.QuerySucceeded);
        Assert.False(result.IsThreat);
    }

    // ---------- OTX ----------

    [Fact]
    public async Task Otx_DetectsFlaggedIp()
    {
        string json = """{"pulse_info":{"count":42},"validation":[]}""";
        var transport = new FakeTransport(json);
        var provider = new AlienVaultOtxProvider(transport);

        var result = await provider.QueryAsync(
            new ThreatQuery(ThreatKind.IpAddress, "1.2.3.4"), "test-key");

        Assert.True(result.QuerySucceeded);
        Assert.True(result.IsThreat);
        Assert.Equal(42, result.DetectionCount);
    }

    [Fact]
    public async Task Otx_CleanIp()
    {
        string json = """{"pulse_info":{"count":0},"validation":[{"detected":false}]}""";
        var transport = new FakeTransport(json);
        var provider = new AlienVaultOtxProvider(transport);

        var result = await provider.QueryAsync(
            new ThreatQuery(ThreatKind.IpAddress, "8.8.8.8"), "test-key");

        Assert.True(result.QuerySucceeded);
        Assert.False(result.IsThreat);
    }

    // ---------- Provider-Eigenschaften ----------

    [Fact]
    public void Providers_RequireKeysCorrectly()
    {
        var providers = new IThreatProvider[]
        {
            new ThreatFoxProvider(new FakeTransport("")),
            new VirusTotalProvider(new FakeTransport("")),
            new SafeBrowsingProvider(new FakeTransport("")),
            new AlienVaultOtxProvider(new FakeTransport(""))
        };

        Assert.False(providers.First(p => p.Id == "threatfox").RequiresApiKey);
        Assert.True(providers.First(p => p.Id == "virustotal").RequiresApiKey);
        Assert.True(providers.First(p => p.Id == "safebrowsing").RequiresApiKey);
        Assert.True(providers.First(p => p.Id == "otx").RequiresApiKey);
    }

    [Fact]
    public void Providers_SupportCorrectKinds()
    {
        Assert.Contains(ThreatKind.Domain, new ThreatFoxProvider(new FakeTransport("")).SupportedKinds);
        Assert.Contains(ThreatKind.FileHash, new ThreatFoxProvider(new FakeTransport("")).SupportedKinds);
        Assert.Contains(ThreatKind.Url, new VirusTotalProvider(new FakeTransport("")).SupportedKinds);
        Assert.Contains(ThreatKind.IpAddress, new AlienVaultOtxProvider(new FakeTransport("")).SupportedKinds);
        Assert.DoesNotContain(ThreatKind.IpAddress, new SafeBrowsingProvider(new FakeTransport("")).SupportedKinds);
    }

    // ---------- Fake ----------

    private sealed class FakeTransport : IHttpTransport
    {
        private readonly string _response;

        public FakeTransport(string response) => _response = response;

        public Task<string> PostFormAsync(string url, IEnumerable<KeyValuePair<string, string>> form,
            string? userAgent = null, CancellationToken ct = default) => Task.FromResult(_response);

        public Task<string> PostJsonAsync(string url, string jsonBody, string? apiKey = null,
            CancellationToken ct = default) => Task.FromResult(_response);

        public Task<string> GetAsync(string url, string? apiKey = null, string? authScheme = null,
            CancellationToken ct = default) => Task.FromResult(_response);
    }
}
