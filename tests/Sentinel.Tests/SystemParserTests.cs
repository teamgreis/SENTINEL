using Sentinel.Core.System;
using Xunit;

namespace Sentinel.Tests;

public class WmiStatusDecoderTests
{
    [Fact]
    public void TypicalDefenderState_IsFullyProtected()
    {
        // Defender aktiv: 0x1100 (on + realtime) + signatures fresh 0x10
        int state = 0x1110;

        Assert.True(WmiStatusDecoder.IsEnabled(state));
        Assert.True(WmiStatusDecoder.IsRealtimeProtectionOn(state));
        Assert.False(WmiStatusDecoder.AreSignaturesStale(state));
    }

    [Fact]
    public void DisabledProduct_Flags()
    {
        int state = 0x0010; // keine Bits für on/realtime

        Assert.False(WmiStatusDecoder.IsEnabled(state));
        Assert.False(WmiStatusDecoder.IsRealtimeProtectionOn(state));
    }

    [Fact]
    public void StaleSignatures_Flagged()
    {
        int state = 0x1100; // on + realtime, aber ohne 0x10

        Assert.True(WmiStatusDecoder.IsEnabled(state));
        Assert.True(WmiStatusDecoder.AreSignaturesStale(state));
    }
}

public class WmiParserTests
{
    [Fact]
    public void ParsesSingleProduct()
    {
        string json = """{"displayName":"Windows Defender","productState":393472}""";

        Assert.True(WmiParser.TryParse(json, out var products));
        Assert.Single(products);
        Assert.Equal("Windows Defender", products[0].DisplayName);
        Assert.Equal(393472, products[0].ProductState);
    }

    [Fact]
    public void ParsesArrayOfProducts()
    {
        string json = """[{"displayName":"Defender","productState":393216},{"displayName":"Other","productState":1}]""";

        Assert.True(WmiParser.TryParse(json, out var products));
        Assert.Equal(2, products.Count);
    }

    [Fact]
    public void InvalidJson_ReturnsFalse()
    {
        Assert.False(WmiParser.TryParse("kein json", out _));
        Assert.False(WmiParser.TryParse("", out _));
    }
}

public class HotFixParserTests
{
    [Fact]
    public void ParsesFreshUpdate()
    {
        string json = """{"HotFixID":"KB5034441","InstalledOn":"01.10.2026 00:00:00"}""";

        Assert.True(HotFixParser.TryParse(json, out var info));
        Assert.Equal("KB5034441", info.HotFixId);
        Assert.NotNull(info.InstalledOn);
    }

    [Fact]
    public void NullDate_StillParses()
    {
        string json = """{"HotFixID":"KB5034441","InstalledOn":null}""";

        Assert.True(HotFixParser.TryParse(json, out var info));
        Assert.Equal("KB5034441", info.HotFixId);
        Assert.Null(info.InstalledOn);
    }

    [Fact]
    public void InvalidJson_ReturnsFalse()
    {
        Assert.False(HotFixParser.TryParse("{kaputt", out _));
    }
}

public class NetworkProfileParserTests
{
    [Fact]
    public void ParsesPublicProfile()
    {
        string json = """{"Name":"WLAN-Zuhause","NetworkCategory":0}""";

        Assert.True(NetworkProfileParser.TryParse(json, out var profiles));
        Assert.Single(profiles);
        Assert.False(profiles[0].IsPrivate);
    }

    [Fact]
    public void ParsesPrivateProfile()
    {
        string json = """{"Name":"LAN","NetworkCategory":1}""";

        Assert.True(NetworkProfileParser.TryParse(json, out var profiles));
        Assert.True(profiles[0].IsPrivate);
    }
}

public class EncryptionParserTests
{
    [Fact]
    public void ParsesFullyEncrypted()
    {
        string json = """{"DriveLetter":"C:","ConversionStatus":1}""";

        Assert.True(EncryptionParser.TryParse(json, out var vol));
        Assert.Equal("C:", vol.DriveLetter);
        Assert.Equal(1, vol.ConversionStatus);
    }

    [Fact]
    public void MissingStatus_Fails()
    {
        string json = """{"DriveLetter":"C:"}""";

        Assert.False(EncryptionParser.TryParse(json, out _));
    }
}

public class AutostartParserTests
{
    [Fact]
    public void CountsRegistryEntries()
    {
        // PowerShell ConvertTo-Json auf Registry-Item: Key-Wert-Paare ohne PS-Prefix
        string json = """{"OneDrive":"C:\\...","SecurityHealth":"C:\\...","PSPath":"...","PSParentPath":"..."}""";

        Assert.Equal(2, AutostartParser.CountEntries(json));
    }

    [Fact]
    public void EmptyJson_Zero()
    {
        Assert.Equal(0, AutostartParser.CountEntries(""));
        Assert.Equal(0, AutostartParser.CountEntries("null"));
    }
}
