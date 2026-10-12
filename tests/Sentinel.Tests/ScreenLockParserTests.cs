using Sentinel.Core.System;
using Xunit;

namespace Sentinel.Tests;

public class ScreenLockParserTests
{
    [Fact]
    public void ParsesActiveLock()
    {
        string output = "ScreenSaveActive : 1\nScreenSaveTimeOut : 600";

        var (active, timeout) = ScreenLockParser.Parse(output);

        Assert.True(active);
        Assert.Equal(600, timeout);
    }

    [Fact]
    public void ParsesDisabledLock()
    {
        string output = "ScreenSaveActive : 0\nScreenSaveTimeOut : 0";

        var (active, timeout) = ScreenLockParser.Parse(output);

        Assert.False(active);
        Assert.Equal(0, timeout);
    }

    [Fact]
    public void EmptyOutput_ReturnsNulls()
    {
        var (active, timeout) = ScreenLockParser.Parse("");

        Assert.Null(active);
        Assert.Null(timeout);
    }

    [Fact]
    public void MissingValues_ReturnNull()
    {
        var (active, timeout) = ScreenLockParser.Parse("irgendwas anderes");

        Assert.Null(active);
        Assert.Null(timeout);
    }
}
