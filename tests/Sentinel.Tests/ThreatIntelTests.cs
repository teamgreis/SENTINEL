using Sentinel.Core.System;
using Sentinel.Core.ThreatIntel;
using Xunit;

namespace Sentinel.Tests;

public class MalwareBazaarParserTests
{
    [Fact]
    public void KnownMalware_IsListed()
    {
        string json = """
        {"query_status":"ok","data":[{"sha256_hash":"abc","signature":"AgentTesla","file_type":"exe","first_seen":"2026-01-01 00:00:00"}]}
        """;

        var result = MalwareBazaarParser.Parse(json, "abc");

        Assert.True(result.IsKnownMalicious);
        Assert.True(result.QuerySucceeded);
        Assert.Equal("AgentTesla", result.Signature);
        Assert.Equal("exe", result.FileType);
        Assert.Contains("AgentTesla", result.Summary);
    }

    [Fact]
    public void UnknownHash_NotListed()
    {
        string json = """{"query_status":"hash_not_found"}""";

        var result = MalwareBazaarParser.Parse(json, "abc");

        Assert.False(result.IsKnownMalicious);
        Assert.True(result.QuerySucceeded);
        Assert.Contains("Kein Eintrag", result.Summary);
    }

    [Fact]
    public void UnexpectedStatus_Fails()
    {
        string json = """{"query_status":"something_weird"}""";

        var result = MalwareBazaarParser.Parse(json, "abc");

        Assert.False(result.IsKnownMalicious);
        Assert.False(result.QuerySucceeded);
    }

    [Fact]
    public void CorruptJson_Fails()
    {
        var result = MalwareBazaarParser.Parse("{kaputt", "abc");

        Assert.False(result.QuerySucceeded);
        Assert.False(result.IsKnownMalicious);
    }

    [Fact]
    public void OkButEmptyData_NotListed()
    {
        string json = """{"query_status":"ok","data":[]}""";

        var result = MalwareBazaarParser.Parse(json, "abc");

        Assert.False(result.IsKnownMalicious);
    }
}

public class UrlHausParserTests
{
    [Fact]
    public void ListedUrl_IsMalicious()
    {
        string json = """
        {"query_status":"ok","url_status":"online","threat":"malware_download"}
        """;

        var result = UrlHausParser.Parse(json, "http://evil.example");

        Assert.True(result.IsKnownMalicious);
        Assert.Equal("malware_download", result.Signature);
    }

    [Fact]
    public void NoResults_NotListed()
    {
        string json = """{"query_status":"no_results"}""";

        var result = UrlHausParser.Parse(json, "http://example.org");

        Assert.False(result.IsKnownMalicious);
        Assert.True(result.QuerySucceeded);
    }

    [Fact]
    public void CorruptJson_Fails()
    {
        var result = UrlHausParser.Parse("kein json", "http://example.org");

        Assert.False(result.QuerySucceeded);
    }
}

public class FileHasherTests
{
    [Fact]
    public void ComputeSha256_IsStable()
    {
        byte[] content = System.Text.Encoding.UTF8.GetBytes("hello world");

        string hash = FileHasher.ComputeSha256(content);

        // Bekannter SHA-256 von "hello world"
        Assert.Equal("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", hash);
    }

    [Fact]
    public void DifferentContent_DifferentHash()
    {
        string a = FileHasher.ComputeSha256(new byte[] { 1, 2, 3 });
        string b = FileHasher.ComputeSha256(new byte[] { 4, 5, 6 });

        Assert.NotEqual(a, b);
    }

    [Fact]
    public async Task ComputeSha256Async_MatchesSync()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sentinel_hash_{Guid.NewGuid():N}.bin");
        try
        {
            await File.WriteAllBytesAsync(path, new byte[] { 9, 8, 7, 6 });
            var async = await FileHasher.ComputeSha256Async(path);
            var sync = FileHasher.ComputeSha256(new byte[] { 9, 8, 7, 6 });
            Assert.Equal(sync, async);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}

public class LocalFileInspectorTests
{
    [Fact]
    public void DetectsExe()
    {
        byte[] header = { 0x4D, 0x5A, 0x90, 0x00 };

        Assert.Equal("Windows EXE (MZ)", LocalFileInspector.DetectType(header));
    }

    [Fact]
    public void DetectsPdf()
    {
        byte[] header = { 0x25, 0x50, 0x44, 0x46, 0x2D };

        Assert.Equal("PDF", LocalFileInspector.DetectType(header));
    }

    [Fact]
    public void UnknownType_ReturnsNull()
    {
        byte[] header = { 0x01, 0x02, 0x03 };

        Assert.Null(LocalFileInspector.DetectType(header));
    }

    [Fact]
    public void Exe_FlagsRisk()
    {
        byte[] content = new byte[] { 0x4D, 0x5A, 0x00, 0x00 };

        var risks = LocalFileInspector.AnalyzeRisks(content);

        Assert.Contains(risks, r => r.Contains("Ausführbare Windows-Datei"));
    }

    [Fact]
    public void OfficeMacro_Flagged()
    {
        byte[] zip = { 0x50, 0x4B, 0x03, 0x04 };
        var payload = zip.Concat(System.Text.Encoding.ASCII.GetBytes("vbaProject.bin")).ToArray();

        var risks = LocalFileInspector.AnalyzeRisks(payload);

        Assert.Contains(risks, r => r.Contains("Makros"));
    }

    [Fact]
    public void PowerShellReference_Flagged()
    {
        var content = System.Text.Encoding.ASCII.GetBytes("something powershell -enc AAAA");

        var risks = LocalFileInspector.AnalyzeRisks(content);

        Assert.Contains(risks, r => r.Contains("PowerShell"));
    }
}

public class ConsentSettingsTests
{
    [Fact]
    public void DefaultIsOff()
    {
        var path = Path.Combine(Path.GetTempPath(), $"consent_{Guid.NewGuid():N}.json");

        var settings = new ConsentSettings(path);

        Assert.False(settings.OnlineAllowed);
    }

    [Fact]
    public void SetAndPersists()
    {
        var path = Path.Combine(Path.GetTempPath(), $"consent2_{Guid.NewGuid():N}.json");
        try
        {
            var settings = new ConsentSettings(path);
            settings.SetOnlineAllowed(true);

            var reloaded = new ConsentSettings(path);
            Assert.True(reloaded.OnlineAllowed);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void RevokeWorks()
    {
        var path = Path.Combine(Path.GetTempPath(), $"consent3_{Guid.NewGuid():N}.json");
        try
        {
            var settings = new ConsentSettings(path);
            settings.SetOnlineAllowed(true);
            settings.SetOnlineAllowed(false);

            Assert.False(new ConsentSettings(path).OnlineAllowed);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void CorruptFile_DefaultsOff()
    {
        var path = Path.Combine(Path.GetTempPath(), $"consent4_{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(path, "kein json{{{");
            Assert.False(new ConsentSettings(path).OnlineAllowed);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}

public class DefenderWmiParserTests
{
    [Fact]
    public void ParsesEnabledState()
    {
        string json = """{"RealTimeProtectionEnabled":true,"AntivirusEnabled":true}""";

        Assert.True(DefenderWmiParser.TryParse(json, out var status));
        Assert.True(status.RealTimeProtectionEnabled);
        Assert.True(status.AntivirusEnabled);
    }

    [Fact]
    public void NumericBooleans_Parsed()
    {
        string json = """{"RealTimeProtectionEnabled":1,"AntivirusEnabled":0}""";

        Assert.True(DefenderWmiParser.TryParse(json, out var status));
        Assert.True(status.RealTimeProtectionEnabled);
        Assert.False(status.AntivirusEnabled);
    }

    [Fact]
    public void CorruptJson_Fails()
    {
        Assert.False(DefenderWmiParser.TryParse("{kaputt", out _));
    }
}
