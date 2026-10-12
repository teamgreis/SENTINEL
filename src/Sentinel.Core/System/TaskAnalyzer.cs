using System.Text.Json;

namespace Sentinel.Core.System;

/// <summary>Analysiert Aufgaben-JSON auf Warnmuster. Reine Logik – testbar ohne Windows.</summary>
public static class TaskAnalyzer
{
    public static List<string> Analyze(string json)
    {
        var findings = new List<string>();
        if (string.IsNullOrWhiteSpace(json)) return findings;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var items = root.ValueKind == JsonValueKind.Array
                ? root.EnumerateArray().ToList()
                : new List<JsonElement> { root };

            foreach (var item in items)
            {
                string name = item.TryGetProperty("TaskName", out var n) ? n.GetString() ?? "?" : "?";
                string exec = item.TryGetProperty("Execute", out var e) ? e.GetString() ?? "" : "";

                string lowExec = exec.ToLowerInvariant();
                if (lowExec.Contains("\\temp\\") || lowExec.Contains("\\tmp\\") || lowExec.Contains("appdata\\local\\temp"))
                    findings.Add($"{name}: startet aus dem Temp-Ordner ({exec}) – ungewöhnlich.");

                if (lowExec.Contains("powershell") || lowExec.Contains("cmd.exe") || lowExec.Contains("wscript") || lowExec.Contains("mshta"))
                    findings.Add($"{name}: startet ein Skript/Interpreter ({exec}) – genau prüfen.");

                if (name.StartsWith(" ", StringComparison.Ordinal) || name.EndsWith(" ", StringComparison.Ordinal))
                    findings.Add($"{name}: Name enthält Leerzeichen an den Rändern – wird zum Verstecken genutzt.");
            }
        }
        catch { }
        return findings;
    }
}

/// <summary>Parst die Ausschluss-JSON-Liste.</summary>
public static class ExclusionsParser
{
    public static List<string> Parse(string json)
    {
        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(json)) return list;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in root.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        var s = item.GetString();
                        if (!string.IsNullOrWhiteSpace(s)) list.Add(s);
                    }
                }
            }
        }
        catch { }
        return list;
    }
}
