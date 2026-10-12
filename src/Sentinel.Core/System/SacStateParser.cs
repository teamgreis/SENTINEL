using RegexNS = System.Text.RegularExpressions.Regex;

namespace Sentinel.Core.System;

/// <summary>Zustand der Smart App Control (SAC).</summary>
public enum SacState
{
    Unknown = -1,

    /// <summary>Aus — keine Prüfung.</summary>
    Off = 0,

    /// <summary>Aktiv (Enforce) — unsignierte/unbekannte Komponenten werden blockiert.</summary>
    Enforce = 1,

    /// <summary>Testmodus (Evaluation) — blockiert nichts, protokolliert nur.</summary>
    Evaluation = 2
}

/// <summary>
/// Signaturstatus einer ausführbaren Datei.
/// </summary>
public enum SignatureState
{
    Unknown,
    Valid,
    NotSigned,
    Invalid
}

/// <summary>
/// Parst SAC- und Signatur-Zustand aus PowerShell/Registry-Ausgaben.
/// Reine Logik – testbar ohne Windows.
/// </summary>
public static class SacStateParser
{
    /// <summary>
    /// Parst einen Zustandswert aus verschieden formatierten Ausgaben:
    /// "1", "1\r\n", "SmartAppControlState : 1", "2"
    /// </summary>
    public static SacState FromOutput(string? output)
    {
        if (string.IsNullOrWhiteSpace(output)) return SacState.Unknown;

        var match = RegexNS.Match(output, @"\b([0-2])\b");
        if (!match.Success) return SacState.Unknown;

        return int.Parse(match.Groups[1].Value) switch
        {
            0 => SacState.Off,
            1 => SacState.Enforce,
            2 => SacState.Evaluation,
            _ => SacState.Unknown
        };
    }

    public static string Describe(SacState state) => state switch
    {
        SacState.Off => "Aus",
        SacState.Enforce => "Aktiv (blockiert)",
        SacState.Evaluation => "Testmodus",
        _ => "Unbekannt"
    };

    /// <summary>Parst den Status von Get-AuthenticodeSignature.</summary>
    public static SignatureState ParseSignatureStatus(string? output)
    {
        if (string.IsNullOrWhiteSpace(output)) return SignatureState.Unknown;

        string trimmed = output.Trim();
        return trimmed switch
        {
            "Valid" => SignatureState.Valid,
            "NotSigned" => SignatureState.NotSigned,
            "HashMismatch" or "NotTrusted" or "UnknownError" => SignatureState.Invalid,
            _ => SignatureState.Unknown
        };
    }
}
