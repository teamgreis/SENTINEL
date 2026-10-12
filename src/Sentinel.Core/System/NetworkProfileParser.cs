using System.Text.Json;

namespace Sentinel.Core.System;

/// <summary>Ein aktives Netzwerkprofil.</summary>
public sealed record NetworkProfileInfo
{
    public string Name { get; init; } = string.Empty;

    /// <summary>0 = Public, 1 = Private, 2 = Domain</summary>
    public int NetworkCategory { get; init; }

    public bool IsPrivate => NetworkCategory >= 1;
}

/// <summary>Parst die JSON-Ausgabe von Get-NetConnectionProfile.</summary>
public static class NetworkProfileParser
{
    public static bool TryParse(string json, out List<NetworkProfileInfo> profiles)
    {
        profiles = new List<NetworkProfileInfo>();
        if (string.IsNullOrWhiteSpace(json)) return false;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.ValueKind == JsonValueKind.Object)
                Add(root, profiles);
            else if (root.ValueKind == JsonValueKind.Array)
                foreach (var item in root.EnumerateArray()) Add(item, profiles);

            return true;
        }
        catch
        {
            return false;
        }

        static void Add(JsonElement e, List<NetworkProfileInfo> list)
        {
            string name = e.TryGetProperty("Name", out var n) ? n.GetString() ?? "?" : "?";
            int cat = e.TryGetProperty("NetworkCategory", out var c) && c.ValueKind == JsonValueKind.Number
                ? c.GetInt32() : 0;
            list.Add(new NetworkProfileInfo { Name = name, NetworkCategory = cat });
        }
    }
}
