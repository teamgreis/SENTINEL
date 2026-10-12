using Sentinel.Core.Baseline;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Erfasst den aktuellen Systemzustand für Baseline-Vergleiche.
/// Alle Abfragen sind read-only.
/// </summary>
public static class BaselineCollector
{
    public static async Task<SystemBaseline> CollectAsync(CancellationToken ct = default)
    {
        var baseline = new SystemBaseline
        {
            MachineName = Environment.MachineName
        };

        // Lokale Benutzer
        var (users, _) = await PowerShell.RunAsync(
            "Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json -Compress", ct)
            .ConfigureAwait(false);
        ParseUsers(baseline, users);

        // Administratoren
        var (admins, _) = await PowerShell.RunAsync(
            "Get-LocalGroupMember -Group Administratoren -ErrorAction SilentlyContinue | Select-Object Name | ConvertTo-Json -Compress", ct)
            .ConfigureAwait(false);
        ParseAdmins(baseline, admins);

        // Dienste mit Starttyp
        var (services, _) = await PowerShell.RunAsync(
            "Get-Service | Select-Object Name,StartType | ConvertTo-Json -Compress", ct)
            .ConfigureAwait(false);
        ParseServices(baseline, services);

        // Autostart HKLM
        var (run, _) = await PowerShell.RunAsync(
            "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -ErrorAction SilentlyContinue | Select-Object -Property * -ExcludeProperty PS* | ConvertTo-Json -Compress", ct)
            .ConfigureAwait(false);
        ParseRunKeys(baseline, run);

        // Freigaben
        var (shares, _) = await PowerShell.RunAsync(
            "Get-SmbShare | Where-Object {$_.Name -notmatch '\\$$'} | Select-Object Name | ConvertTo-Json -Compress", ct)
            .ConfigureAwait(false);
        ParseShares(baseline, shares);

        // Geplante Aufgaben (nicht Microsoft)
        var (tasks, _) = await PowerShell.RunAsync(
            "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.TaskPath -notlike '\\Microsoft*'} | Select-Object TaskName,TaskPath | ConvertTo-Json -Compress", ct)
            .ConfigureAwait(false);
        ParseTasks(baseline, tasks);

        // Firewall-Regeln (nur Allow-Inbound, das sind die riskanten)
        var (rules, _) = await PowerShell.RunAsync(
            "Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Select-Object DisplayName | ConvertTo-Json -Compress", ct)
            .ConfigureAwait(false);
        ParseFirewallRules(baseline, rules);

        return baseline;
    }

    private static void ParseUsers(SystemBaseline b, string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            void AddOne(System.Text.Json.JsonElement e)
            {
                string name = e.TryGetProperty("Name", out var n) ? n.GetString() ?? "?" : "?";
                bool enabled = !e.TryGetProperty("Enabled", out var en) ||
                               en.ValueKind == System.Text.Json.JsonValueKind.True;
                b.LocalUsers[name] = enabled;
            }

            if (root.ValueKind == System.Text.Json.JsonValueKind.Object) AddOne(root);
            else if (root.ValueKind == System.Text.Json.JsonValueKind.Array)
                foreach (var item in root.EnumerateArray()) AddOne(item);
        }
        catch { }
    }

    private static void ParseAdmins(SystemBaseline b, string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            void AddOne(System.Text.Json.JsonElement e)
            {
                string name = e.TryGetProperty("Name", out var n) ? n.GetString() ?? "?" : "?";
                b.Administrators.Add(name);
            }

            if (root.ValueKind == System.Text.Json.JsonValueKind.Object) AddOne(root);
            else if (root.ValueKind == System.Text.Json.JsonValueKind.Array)
                foreach (var item in root.EnumerateArray()) AddOne(item);
        }
        catch { }
    }

    private static void ParseServices(SystemBaseline b, string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            void AddOne(System.Text.Json.JsonElement e)
            {
                string name = e.TryGetProperty("Name", out var n) ? n.GetString() ?? "?" : "?";
                string start = e.TryGetProperty("StartType", out var s) ? s.GetString() ?? "?" : "?";
                b.Services[name] = start;
            }

            if (root.ValueKind == System.Text.Json.JsonValueKind.Object) AddOne(root);
            else if (root.ValueKind == System.Text.Json.JsonValueKind.Array)
                foreach (var item in root.EnumerateArray()) AddOne(item);
        }
        catch { }
    }

    private static void ParseRunKeys(SystemBaseline b, string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Name.StartsWith("PS", StringComparison.OrdinalIgnoreCase)) continue;
                b.AutostartEntries[prop.Name] = prop.Value.ToString();
            }
        }
        catch { }
    }

    private static void ParseShares(SystemBaseline b, string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            void AddOne(System.Text.Json.JsonElement e)
            {
                string name = e.TryGetProperty("Name", out var n) ? n.GetString() ?? "?" : "?";
                b.NetworkShares.Add(name);
            }

            if (root.ValueKind == System.Text.Json.JsonValueKind.Object) AddOne(root);
            else if (root.ValueKind == System.Text.Json.JsonValueKind.Array)
                foreach (var item in root.EnumerateArray()) AddOne(item);
        }
        catch { }
    }

    private static void ParseTasks(SystemBaseline b, string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            void AddOne(System.Text.Json.JsonElement e)
            {
                string name = e.TryGetProperty("TaskName", out var n) ? n.GetString() ?? "?" : "?";
                string path = e.TryGetProperty("TaskPath", out var p) ? p.GetString() ?? "" : "";
                b.ScheduledTasks[name] = path;
            }

            if (root.ValueKind == System.Text.Json.JsonValueKind.Object) AddOne(root);
            else if (root.ValueKind == System.Text.Json.JsonValueKind.Array)
                foreach (var item in root.EnumerateArray()) AddOne(item);
        }
        catch { }
    }

    private static void ParseFirewallRules(SystemBaseline b, string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            void AddOne(System.Text.Json.JsonElement e)
            {
                string name = e.TryGetProperty("DisplayName", out var n) ? n.GetString() ?? "?" : "?";
                b.FirewallRules[name] = "Allow-Inbound";
            }

            if (root.ValueKind == System.Text.Json.JsonValueKind.Object) AddOne(root);
            else if (root.ValueKind == System.Text.Json.JsonValueKind.Array)
                foreach (var item in root.EnumerateArray()) AddOne(item);
        }
        catch { }
    }
}
