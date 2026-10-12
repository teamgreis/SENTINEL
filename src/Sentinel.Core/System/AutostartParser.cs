using System.Text.Json;

namespace Sentinel.Core.System;

/// <summary>Zählt Einträge in der Run-Registry aus JSON-Output.</summary>
public static class AutostartParser
{
    /// <summary>Zählt Registrierungseinträge (ohne PS-Metadaten).</summary>
    public static int CountEntries(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return 0;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.ValueKind == JsonValueKind.Object)
            {
                return CountProperties(root);
            }
            if (root.ValueKind == JsonValueKind.Array)
            {
                int total = 0;
                foreach (var item in root.EnumerateArray())
                    total += CountProperties(item);
                return total;
            }
        }
        catch { }
        return 0;
    }

    private static int CountProperties(JsonElement obj)
    {
        // PowerShell ConvertTo-Json auf Registry-Items: Keys ohne PS*-Prefix
        int count = 0;
        foreach (var prop in obj.EnumerateObject())
        {
            if (prop.Name.StartsWith("PS", StringComparison.OrdinalIgnoreCase)) continue;
            count++;
        }
        return count;
    }
}
