using Sentinel.Core.UrlCheck;
using Xunit;

namespace Sentinel.Tests;

public class UrlAnalyzerTests
{
    private readonly UrlAnalyzer _analyzer = new();

    [Theory]
    [InlineData("https://www.google.com", UrlVerdict.LooksOkay)]
    [InlineData("https://example.org", UrlVerdict.LooksOkay)]
    public void CleanUrls_LookOkay(string url, UrlVerdict expected)
    {
        Assert.Equal(expected, _analyzer.Analyze(url).Verdict);
    }

    [Fact]
    public void ImpostorDomain_IsFlagged()
    {
        var report = _analyzer.Analyze("https://paypa1.de/login");

        Assert.Equal(UrlVerdict.Dangerous, report.Verdict);
        Assert.Contains(report.Findings, f => f.Title.Contains("Ziffernersatz"));
    }

    [Fact]
    public void HomoglyphHost_IsFlagged()
    {
        // "gооgle" mit kyrillischem о
        var report = _analyzer.Analyze("https://gооgle.com/login");

        Assert.Contains(report.Findings, f => f.Title.Contains("Homoglyph"));
    }

    [Fact]
    public void HttpOnly_IsFlaggedAsMedium()
    {
        var report = _analyzer.Analyze("http://example.com");

        Assert.Contains(report.Findings, f => f.Title.Contains("verschlüsselte"));
    }

    [Fact]
    public void IpHost_IsFlagged()
    {
        var report = _analyzer.Analyze("http://192.168.1.100/login");

        Assert.Contains(report.Findings, f => f.Title.Contains("IP-Adresse"));
    }

    [Fact]
    public void AtSignTrick_IsFlagged()
    {
        var report = _analyzer.Analyze("https://www.bank.de@evil.ru");

        Assert.Contains(report.Findings, f => f.Title.Contains("@-Trick"));
    }

    [Fact]
    public void BrandNotMainDomain_IsFlagged()
    {
        var report = _analyzer.Analyze("https://microsoft.evil-domain.com/login");

        Assert.Contains(report.Findings, f => f.Title.Contains("außerhalb der echten Domain"));
    }

    [Fact]
    public void EmptyInput_IsInvalid()
    {
        Assert.Equal(UrlVerdict.Invalid, _analyzer.Analyze("").Verdict);
        Assert.Equal(UrlVerdict.Invalid, _analyzer.Analyze(null!).Verdict);
    }

    [Fact]
    public void SuspiciousTld_IsFlagged()
    {
        var report = _analyzer.Analyze("https://freiespiel.zip");

        Assert.Contains(report.Findings, f => f.Title.Contains("Domain-Endung"));
    }

    [Fact]
    public void RealBrandAsMainDomain_NotFlaggedAsImpostor()
    {
        // paypal.com selbst ist KEIN Impostor
        var report = _analyzer.Analyze("https://paypal.com/login");

        Assert.DoesNotContain(report.Findings, f => f.Title.Contains("Ziffernersatz"));
        Assert.DoesNotContain(report.Findings, f => f.Title.Contains("außerhalb der echten Domain"));
    }
}
