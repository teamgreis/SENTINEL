using Sentinel.Core.System;
using Xunit;

namespace Sentinel.Tests;

/// <summary>Tests für sprachrobuste Parser der neuen Checks.</summary>
public class NewCheckParserTests
{
    // Lockout-Schwelle: "Sperrschwelle: 5" / "Lockout threshold: 5" / "Sperrschwelle: 0"
    [Theory]
    [InlineData("Sperrschwelle: 5", 5)]
    [InlineData("Lockout threshold: 5", 5)]
    [InlineData("Sperrschwelle: 0", 0)]
    [InlineData("Lockout threshold: 0", 0)]
    [InlineData("Sperrschwelle: 15", 15)]
    [InlineData("irrelevant", -1)]
    public void LockoutThreshold_Parsed(string line, int expected)
    {
        int actual = LockoutPolicyParser.ParseThreshold(line);
        Assert.Equal(expected, actual);
    }

    // Basisdatum-Parser (Passwort-Alter)
    [Theory]
    [InlineData("12.10.2026", 2026, 10, 12)]
    [InlineData("01.01.2020", 2020, 1, 1)]
    public void DateRegex_MatchesEuropeanFormat(string text, int year, int month, int day)
    {
        var match = System.Text.RegularExpressions.Regex.Match(text, @"(\d{1,2})[./](\d{1,2})[./](\d{4})");

        Assert.True(match.Success);
        Assert.Equal(year, int.Parse(match.Groups[3].Value));
        Assert.Equal(month, int.Parse(match.Groups[2].Value));
        Assert.Equal(day, int.Parse(match.Groups[1].Value));
    }

    [Theory]
    [InlineData("10/12/2026", true)]
    [InlineData("10.12.2026", true)]
    [InlineData("nie", false)]
    public void DateRegex_OnlyMatchesDates(string text, bool shouldMatch)
    {
        var match = System.Text.RegularExpressions.Regex.Match(text, @"(\d{1,2})[./](\d{1,2})[./](\d{4})");
        Assert.Equal(shouldMatch, match.Success);
    }
}
