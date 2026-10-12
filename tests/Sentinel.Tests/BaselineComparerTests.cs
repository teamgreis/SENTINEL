using Sentinel.Core.Baseline;
using Xunit;

namespace Sentinel.Tests;

public class BaselineComparerTests
{
    private static SystemBaseline Empty() => new();

    private static SystemBaseline WithUser(string name, bool admin = false)
    {
        var b = new SystemBaseline();
        b.LocalUsers[name] = true;
        if (admin) b.Administrators.Add(name);
        return b;
    }

    [Fact]
    public void IdenticalBaselines_NoDeviations()
    {
        var a = WithUser("felix");
        var b = WithUser("felix");

        var result = BaselineComparer.Compare(a, b);

        Assert.False(result.HasDeviations);
        Assert.Equal(0, result.MaxSuspicion);
    }

    [Fact]
    public void NewAdmin_IsHighSuspicion()
    {
        var baseline = WithUser("felix");
        var current = WithUser("felix");
        current.Administrators.Add("hacker");

        var result = BaselineComparer.Compare(baseline, current);

        var deviation = Assert.Single(result.Notable);
        Assert.Equal(DeviationType.NewAdmin, deviation.Type);
        Assert.True(deviation.Suspicion >= 8);
    }

    [Fact]
    public void NewAutostart_IsFlagged()
    {
        var baseline = new SystemBaseline();
        baseline.AutostartEntries["OneDrive"] = "C:\\od.exe";

        var current = new SystemBaseline();
        current.AutostartEntries["OneDrive"] = "C:\\od.exe";
        current.AutostartEntries["Evil"] = "C:\\temp\\evil.exe";

        var result = BaselineComparer.Compare(baseline, current);

        Assert.Contains(result.Deviations, d =>
            d.Type == DeviationType.NewAutostart && d.Item == "Evil");
    }

    [Fact]
    public void ChangedAutostartPath_IsFlagged()
    {
        var baseline = new SystemBaseline();
        baseline.AutostartEntries["Updater"] = "C:\\good\\u.exe";

        var current = new SystemBaseline();
        current.AutostartEntries["Updater"] = "C:\\evil\\u.exe";

        var result = BaselineComparer.Compare(baseline, current);

        Assert.Contains(result.Deviations, d => d.Type == DeviationType.ChangedAutostart);
    }

    [Fact]
    public void NewService_IsFlagged()
    {
        var baseline = new SystemBaseline();
        baseline.Services["wuauserv"] = "Auto";

        var current = new SystemBaseline();
        current.Services["wuauserv"] = "Auto";
        current.Services["evilsvc"] = "Auto";

        var result = BaselineComparer.Compare(baseline, current);

        Assert.Contains(result.Deviations, d =>
            d.Type == DeviationType.NewService && d.Item == "evilsvc");
    }

    [Fact]
    public void ChangedServiceStartType_IsFlagged()
    {
        var baseline = new SystemBaseline();
        baseline.Services["defender"] = "Auto";

        var current = new SystemBaseline();
        current.Services["defender"] = "Disabled";

        var result = BaselineComparer.Compare(baseline, current);

        Assert.Contains(result.Deviations, d => d.Type == DeviationType.ChangedServiceStartType);
    }

    [Fact]
    public void RemovedUser_IsLowSuspicion()
    {
        var baseline = WithUser("olduser");
        var current = new SystemBaseline();

        var result = BaselineComparer.Compare(baseline, current);

        Assert.Contains(result.Deviations, d => d.Type == DeviationType.RemovedUser);
        Assert.DoesNotContain(result.Deviations, d => d.Suspicion >= 5);
    }

    [Fact]
    public void NewFirewallRule_IsFlagged()
    {
        var baseline = new SystemBaseline();
        var current = new SystemBaseline();
        current.FirewallRules["Evil Rule"] = "Allow-Inbound";

        var result = BaselineComparer.Compare(baseline, current);

        Assert.Contains(result.Deviations, d => d.Type == DeviationType.NewFirewallRule);
    }

    [Fact]
    public void NewShare_IsFlagged()
    {
        var baseline = new SystemBaseline();
        baseline.NetworkShares.Add("public");
        var current = new SystemBaseline();
        current.NetworkShares.Add("public");
        current.NetworkShares.Add("secret");

        var result = BaselineComparer.Compare(baseline, current);

        Assert.Contains(result.Deviations, d => d.Type == DeviationType.NewShare);
    }

    [Fact]
    public void Serialization_RoundTrips()
    {
        var baseline = new SystemBaseline
        {
            MachineName = "testpc"
        };
        baseline.LocalUsers["felix"] = true;
        baseline.Administrators.Add("felix");
        baseline.Services["test"] = "Auto";
        baseline.AutostartEntries["app"] = "C:\\app.exe";
        baseline.NetworkShares.Add("docs");
        baseline.ScheduledTasks["task1"] = "\\Custom";
        baseline.FirewallRules["rule1"] = "Allow-Inbound";

        var json = baseline.ToJson();
        var loaded = SystemBaseline.FromJson(json);

        Assert.NotNull(loaded);
        Assert.Equal("testpc", loaded!.MachineName);
        Assert.True(loaded.LocalUsers.ContainsKey("felix"));
        Assert.Contains("felix", loaded.Administrators);
        Assert.Equal("Auto", loaded.Services["test"]);
        Assert.Equal("C:\\app.exe", loaded.AutostartEntries["app"]);
        Assert.Contains("docs", loaded.NetworkShares);
        Assert.Equal("\\Custom", loaded.ScheduledTasks["task1"]);
        Assert.Equal("Allow-Inbound", loaded.FirewallRules["rule1"]);
    }

    [Fact]
    public void FromCorruptJson_ReturnsNull()
    {
        Assert.Null(SystemBaseline.FromJson("{kaputt"));
    }

    [Fact]
    public void DeviationDescribe_Works()
    {
        var d = new BaselineDeviation
        {
            Type = DeviationType.NewAdmin, Item = "hacker"
        };

        Assert.Contains("hacker", d.Describe());
    }
}
