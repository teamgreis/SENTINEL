using System.Text.Json;

namespace Sentinel.Core.System;

/// <summary>Ein HotFix-Eintrag (Windows-Update).</summary>
public sealed record HotFixInfo
{
    public string HotFixId { get; init; } = string.Empty;
    public DateTime? InstalledOn { get; init; }
}

/// <summary>Parst die JSON-Ausgabe von Get-HotFix. Bewusst getrennt für Testbarkeit.</summary>
public static class HotFixParser
{
    public static bool TryParse(string json, out HotFixInfo info)
    {
        info = new HotFixInfo();
        if (string.IsNullOrWhiteSpace(json)) return false;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string id = root.TryGetProperty("HotFixID", out var idEl) ? idEl.GetString() ?? "?" : "?";

            DateTime? installed = null;
            if (root.TryGetProperty("InstalledOn", out var d) && d.ValueKind == JsonValueKind.String)
            {
                var raw = d.GetString();
                if (!string.IsNullOrWhiteSpace(raw) && DateTime.TryParse(raw, out var parsed))
                    installed = parsed;
            }

            info = new HotFixInfo { HotFixId = id, InstalledOn = installed };
            return id != "?" || installed is not null;
        }
        catch
        {
            return false;
        }
    }
}
