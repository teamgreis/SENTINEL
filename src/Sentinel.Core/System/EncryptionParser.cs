using System.Text.Json;

namespace Sentinel.Core.System;

/// <summary>Ein verschlüsselbares Volume.</summary>
public sealed record EncryptableVolume
{
    public string DriveLetter { get; init; } = string.Empty;
    public int ConversionStatus { get; init; }
}

/// <summary>Parst die JSON-Ausgabe der BitLocker-WMI-Abfrage.</summary>
public static class EncryptionParser
{
    // 1 = vollständig verschlüsselt, 0 = vollständig entschlüsselt,
    // 2 = verschlüsselt (mit freiem Speicher entschlüsselt), andere = in Arbeit
    public static bool TryParse(string json, out EncryptableVolume vol)
    {
        vol = new EncryptableVolume();
        if (string.IsNullOrWhiteSpace(json)) return false;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string drive = root.TryGetProperty("DriveLetter", out var d) ? d.GetString() ?? "" : "";
            int status = root.TryGetProperty("ConversionStatus", out var s) && s.ValueKind == JsonValueKind.Number
                ? s.GetInt32() : -1;

            vol = new EncryptableVolume { DriveLetter = drive, ConversionStatus = status };
            return status >= 0;
        }
        catch
        {
            return false;
        }
    }
}
