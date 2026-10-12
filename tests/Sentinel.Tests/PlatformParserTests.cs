using Sentinel.Core.System;
using Xunit;

namespace Sentinel.Tests;

public class TaskAnalyzerTests
{
    [Fact]
    public void TempPathTask_IsFlagged()
    {
        string json = """[{"TaskName":"Updater","TaskPath":"\\Custom","Execute":"C:\\Users\\x\\AppData\\Local\\Temp\\u.exe"}]""";

        var findings = TaskAnalyzer.Analyze(json);

        Assert.Contains(findings, f => f.Contains("Temp-Ordner"));
    }

    [Fact]
    public void PowerShellTask_IsFlagged()
    {
        string json = """[{"TaskName":"Mystery","TaskPath":"\\Custom","Execute":"powershell.exe"}]""";

        var findings = TaskAnalyzer.Analyze(json);

        Assert.Contains(findings, f => f.Contains("Interpreter"));
    }

    [Fact]
    public void PaddedName_IsFlagged()
    {
        string json = """[{"TaskName":"Harmlos ","TaskPath":"\\Custom","Execute":"C:\\app.exe"}]""";

        var findings = TaskAnalyzer.Analyze(json);

        Assert.Contains(findings, f => f.Contains("Leerzeichen"));
    }

    [Fact]
    public void CleanTask_NotFlagged()
    {
        string json = """[{"TaskName":"AdobeUpdater","TaskPath":"\\Custom","Execute":"C:\\Program Files\\Adobe\\updater.exe"}]""";

        var findings = TaskAnalyzer.Analyze(json);

        Assert.Empty(findings);
    }

    [Fact]
    public void EmptyOrCorrupt_ReturnsEmpty()
    {
        Assert.Empty(TaskAnalyzer.Analyze(""));
        Assert.Empty(TaskAnalyzer.Analyze("kaputt{{{"));
    }
}

public class ExclusionsParserTests
{
    [Fact]
    public void ParsesArray()
    {
        string json = """["C:\\Windows\\Temp","powershell.exe","*.log"]""";

        var list = ExclusionsParser.Parse(json);

        Assert.Equal(3, list.Count);
        Assert.Contains("C:\\Windows\\Temp", list);
    }

    [Fact]
    public void EmptyInput_ReturnsEmpty()
    {
        Assert.Empty(ExclusionsParser.Parse(""));
        Assert.Empty(ExclusionsParser.Parse("kaputt"));
    }
}
