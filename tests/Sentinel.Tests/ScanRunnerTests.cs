using Sentinel.Core.Checks;
using Sentinel.Core.Reporting;
using Xunit;

namespace Sentinel.Tests;

/// <summary>Testhilfs-Check für Runner- und Export-Tests.</summary>
public sealed class FakeCheck : ICheck
{
    private readonly CheckStatus _status;
    public FakeCheck(string id, CheckStatus status, CheckWeight weight = CheckWeight.Normal)
    {
        Id = id; _status = status; Weight = weight;
        Title = id;
    }
    public string Id { get; }
    public string Title { get; }
    public CheckWeight Weight { get; }
    public string Description => "test";

    public Task<CheckResult> RunAsync(CancellationToken ct = default) =>
        Task.FromResult(new CheckResult
        {
            Id = Id, Title = Title, Status = _status, Weight = Weight,
            Detail = "d", Explanation = "e"
        });
}

public sealed class ThrowingCheck : ICheck
{
    public string Id => "boom";
    public string Title => "Boom";
    public CheckWeight Weight => CheckWeight.High;
    public string Description => "throws";
    public Task<CheckResult> RunAsync(CancellationToken ct = default) =>
        throw new InvalidOperationException("kaputt");
}

public class ScanRunnerTests
{
    [Fact]
    public async Task RunCollectsAllResultsAndScore()
    {
        var runner = new ScanRunner(new ICheck[]
        {
            new FakeCheck("a", CheckStatus.Pass),
            new FakeCheck("b", CheckStatus.Fail)
        });

        var report = await runner.RunAsync();

        Assert.Equal(2, report.Results.Count);
        Assert.Equal(50, report.Score.Value);
        Assert.NotEmpty(runner.Log);
    }

    [Fact]
    public async Task FailingCheckBecomesUnknownWithoutBreakingScan()
    {
        var runner = new ScanRunner(new ICheck[]
        {
            new ThrowingCheck(),
            new FakeCheck("b", CheckStatus.Pass)
        });

        var report = await runner.RunAsync();

        Assert.Equal(2, report.Results.Count);
        Assert.Equal(CheckStatus.Unknown, report.Results[0].Status);
        // Der eine bewertbare Pass gibt 100 %
        Assert.Equal(100, report.Score.Value);
    }

    [Fact]
    public async Task CancellationStopsScan()
    {
        var runner = new ScanRunner(new ICheck[]
        {
            new FakeCheck("a", CheckStatus.Pass),
            new FakeCheck("b", CheckStatus.Pass)
        });
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() => runner.RunAsync(cts.Token));
    }
}

public class ReportExporterTests
{
    [Fact]
    public async Task ExportRoundTrip()
    {
        var runner = new ScanRunner(new ICheck[]
        {
            new FakeCheck("system.firewall", CheckStatus.Pass, CheckWeight.High)
        });
        var report = await runner.RunAsync();

        var path = Path.Combine(Path.GetTempPath(), $"sentinel_test_{Guid.NewGuid():N}.txt");
        try
        {
            await ReportExporter.SaveAsync(report, path);
            var text = await File.ReadAllTextAsync(path);

            Assert.Contains("SENTINEL — Sicherheitsbericht", text);
            Assert.Contains("Gesamt-Score", text);
            Assert.Contains("system.firewall", text);
            Assert.Contains("Orientierung", text); // Disclaimer
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
