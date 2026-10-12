using Sentinel.Core.Checks;
using Sentinel.Core.Scoring;
using Xunit;

namespace Sentinel.Tests;

public class ScoreCalculatorTests
{
    private static CheckResult Result(string id, CheckStatus status, CheckWeight weight = CheckWeight.Normal) =>
        new()
        {
            Id = id, Title = id, Status = status, Weight = weight,
            Detail = "d", Explanation = "e"
        };

    [Fact]
    public void AllPass_Gives100()
    {
        var score = ScoreCalculator.Calculate(new[]
        {
            Result("a", CheckStatus.Pass), Result("b", CheckStatus.Pass, CheckWeight.High)
        });

        Assert.Equal(100, score.Value);
        Assert.Equal(ScoreGrade.Gut, score.Grade);
        Assert.Equal(2, score.Passed);
        Assert.Equal(2, score.Graded);
    }

    [Fact]
    public void AllFail_Gives0()
    {
        var score = ScoreCalculator.Calculate(new[] { Result("a", CheckStatus.Fail) });

        Assert.Equal(0, score.Value);
        Assert.Equal(ScoreGrade.Kritisch, score.Grade);
        Assert.Equal(1, score.Failed);
    }

    [Fact]
    public void Warning_GivesHalfPoints()
    {
        var score = ScoreCalculator.Calculate(new[]
        {
            Result("a", CheckStatus.Pass), Result("b", CheckStatus.Warning)
        });

        Assert.Equal(75, score.Value);
        Assert.Equal(1, score.Warnings);
    }

    [Fact]
    public void InfoAndUnknown_AreNotGraded()
    {
        var score = ScoreCalculator.Calculate(new[]
        {
            Result("a", CheckStatus.Pass),
            Result("b", CheckStatus.Info),
            Result("c", CheckStatus.Unknown)
        });

        Assert.Equal(100, score.Value);
        Assert.Equal(1, score.Graded);
        Assert.Equal(1, score.Info);
        Assert.Equal(1, score.Unknown);
    }

    [Fact]
    public void WeightImpactsScore()
    {
        // Hohes Gewicht fehlgeschlagen wiegt mehr als niedriges bestanden
        var score = ScoreCalculator.Calculate(new[]
        {
            Result("low", CheckStatus.Pass, CheckWeight.Low),
            Result("high", CheckStatus.Fail, CheckWeight.High)
        });

        // 10 von 40 Punkten = 25 %
        Assert.Equal(25, score.Value);
        Assert.Equal(ScoreGrade.Kritisch, score.Grade);
    }

    [Fact]
    public void EmptyResults_GivesUnknownGrade()
    {
        var score = ScoreCalculator.Calculate(Array.Empty<CheckResult>());

        Assert.Equal(0, score.Value);
        Assert.Equal(ScoreGrade.Unbekannt, score.Grade);
    }

    [Fact]
    public void ContributionsAreTraceable()
    {
        var score = ScoreCalculator.Calculate(new[]
        {
            Result("a", CheckStatus.Pass, CheckWeight.High),
            Result("b", CheckStatus.Fail)
        });

        var c = score.Contributions.Single(x => x.CheckId == "a");
        Assert.Equal(CheckWeight.High, c.Weight);
        Assert.Equal(30, c.Max);
        Assert.Equal(30, c.Earned);
    }
}
