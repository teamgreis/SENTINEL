using Sentinel.Core.System;
using Xunit;

namespace Sentinel.Tests;

public class SacStateParserTests
{
    [Theory]
    [InlineData("1", SacState.Enforce)]
    [InlineData("1\r\n", SacState.Enforce)]
    [InlineData("2", SacState.Evaluation)]
    [InlineData("0", SacState.Off)]
    public void ParsesBareNumbers(string output, SacState expected)
    {
        Assert.Equal(expected, SacStateParser.FromOutput(output));
    }

    [Theory]
    [InlineData("SmartAppControlState : 1", SacState.Enforce)]
    [InlineData("SmartAppControlState : 2", SacState.Evaluation)]
    [InlineData("SmartAppControlState : 0", SacState.Off)]
    public void ParsesPowerShellFormat(string output, SacState expected)
    {
        Assert.Equal(expected, SacStateParser.FromOutput(output));
    }

    [Theory]
    [InlineData("", SacState.Unknown)]
    [InlineData("  ", SacState.Unknown)]
    [InlineData("abc", SacState.Unknown)]
    [InlineData(null, SacState.Unknown)]
    public void InvalidInput_Unknown(string? output, SacState expected)
    {
        Assert.Equal(expected, SacStateParser.FromOutput(output));
    }

    [Fact]
    public void Describe_KnownStates()
    {
        Assert.Contains("Aktiv", SacStateParser.Describe(SacState.Enforce));
        Assert.Contains("Testmodus", SacStateParser.Describe(SacState.Evaluation));
        Assert.Contains("Aus", SacStateParser.Describe(SacState.Off));
    }

    [Theory]
    [InlineData("Valid", SignatureState.Valid)]
    [InlineData("NotSigned", SignatureState.NotSigned)]
    [InlineData("HashMismatch", SignatureState.Invalid)]
    [InlineData("NotTrusted", SignatureState.Invalid)]
    [InlineData("irgendwas", SignatureState.Unknown)]
    [InlineData("", SignatureState.Unknown)]
    [InlineData(null, SignatureState.Unknown)]
    public void ParsesSignatureStatus(string? output, SignatureState expected)
    {
        Assert.Equal(expected, SacStateParser.ParseSignatureStatus(output));
    }
}
