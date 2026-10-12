using System.Text.Json;

namespace Sentinel.Core.System;

/// <summary>Statuswerte aus dem Defender-WMI-Provider.</summary>
public sealed record DefenderWmiStatus
{
    public bool RealTimeProtectionEnabled { get; init; }
    public bool AntivirusEnabled { get; init; }
    public DateTime? SignatureLastUpdated { get; init; }
}

/// <summary>Parst die JSON-Ausgabe von MSFT_MpComputerStatus.</summary>
public static class DefenderWmiParser
{
    public static bool TryParse(string json, out DefenderWmiStatus status)
    {
        status = new DefenderWmiStatus();
        if (string.IsNullOrWhiteSpace(json)) return false;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            bool rtp = root.TryGetProperty("RealTimeProtectionEnabled", out var r) &&
                       (r.ValueKind == JsonValueKind.True ||
                        (r.ValueKind == JsonValueKind.Number && r.GetInt32() == 1));
            bool av = root.TryGetProperty("AntivirusEnabled", out var a) &&
                      (a.ValueKind == JsonValueKind.True ||
                       (a.ValueKind == JsonValueKind.Number && a.GetInt32() == 1));

            DateTime? updated = null;
            if (root.TryGetProperty("AntivirusSignatureLastUpdated", out var u) && u.ValueKind == JsonValueKind.String)
            {
                if (DateTime.TryParse(u.GetString(), out var parsed))
                    updated = parsed;
            }

            status = new DefenderWmiStatus
            {
                RealTimeProtectionEnabled = rtp,
                AntivirusEnabled = av,
                SignatureLastUpdated = updated
            };
            return true;
        }
        catch
        {
            return false;
        }
    }
}
