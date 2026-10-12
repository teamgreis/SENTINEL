using System.Management;

namespace Sentinel.Platform.Users;

/// <summary>
/// Liest die lokalen Windows-Benutzerkonten über WMI (read-only).
/// Ermöglicht den Import als Sentinel-Nutzer.
/// </summary>
public static class WindowsUserReader
{
    /// <summary>Ein lokales Windows-Konto.</summary>
    public sealed record WindowsAccount
    {
        public required string Name { get; init; }
        public string? FullName { get; init; }
        public bool Disabled { get; init; }
        public bool IsAdministrator { get; init; }

        /// <summary>System-interne Konten (SYSTEM, NETZWERKDIENST etc.).</summary>
        public bool IsBuiltInSystem { get; init; }
    }

    /// <summary>
    /// Liest alle lokalen Konten. Systeminterne Konten werden gefiltert,
    /// können aber mit includeSystem angezeigt werden.
    /// </summary>
    public static IReadOnlyList<WindowsAccount> GetLocalAccounts(bool includeSystem = false)
    {
        var accounts = new List<WindowsAccount>();

        try
        {
            // 1) Konten über Win32_UserAccount (lokal)
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, FullName, Disabled, LocalAccount, SID FROM Win32_UserAccount WHERE LocalAccount=True");

            foreach (var o in searcher.Get())
            {
                using var obj = (ManagementObject)o;
                string name = obj["Name"]?.ToString() ?? "";
                if (string.IsNullOrEmpty(name)) continue;

                bool disabled = obj["Disabled"] is true;
                string? sid = obj["SID"]?.ToString();
                bool isSystem = IsSystemSid(sid);

                if (isSystem && !includeSystem) continue;

                accounts.Add(new WindowsAccount
                {
                    Name = name,
                    FullName = obj["FullName"]?.ToString(),
                    Disabled = disabled,
                    IsAdministrator = IsInAdminGroup(name),
                    IsBuiltInSystem = isSystem
                });
            }

            // 2) Administratoren-Gruppe prüfen
            var adminNames = GetAdminGroupMembers();
            foreach (var acc in accounts)
            {
                if (adminNames.Contains(acc.Name, StringComparer.OrdinalIgnoreCase))
                {
                    // IsAdministrator ist init-only – neu erzeugen
                    int idx = accounts.IndexOf(acc);
                    accounts[idx] = acc with { IsAdministrator = true };
                }
            }
        }
        catch
        {
            // WMI nicht verfügbar (selten, aber möglich bei Berechtigungsproblemen)
        }

        return accounts;
    }

    /// <summary>Nur die aktivierten, nicht-System-Konten.</summary>
    public static IReadOnlyList<WindowsAccount> GetImportableAccounts()
        => GetLocalAccounts()
            .Where(a => !a.Disabled && !a.IsBuiltInSystem)
            .ToList();

    private static bool IsSystemSid(string? sid)
    {
        // Bekannte System-SIDs: S-1-5-18 (SYSTEM), S-1-5-19, S-1-5-20 (Dienste),
        // WDAGUtilityAccount, defaultuser0 etc.
        if (string.IsNullOrEmpty(sid)) return false;
        if (sid.StartsWith("S-1-5-18") || sid.StartsWith("S-1-5-19") || sid.StartsWith("S-1-5-20"))
            return true;
        return false;
    }

    private static bool IsInAdminGroup(string userName)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT PartComponent FROM Win32_GroupUser WHERE GroupComponent=\"Win32_Group.Domain='{Environment.MachineName}',Name='Administratoren'\"");

            foreach (var o in searcher.Get())
            {
                using var obj = (ManagementObject)o;
                string? part = obj["PartComponent"]?.ToString() ?? "";
                // Format: \\PC\root\cimv2:Win32_UserAccount.Domain="PC",Name="Admin"
                if (part.Contains($"Name=\"{userName}\"", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        catch
        {
            // Gruppe nicht lesbar
        }
        return false;
    }

    private static HashSet<string> GetAdminGroupMembers()
    {
        var members = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT PartComponent FROM Win32_GroupUser WHERE GroupComponent=\"Win32_Group.Domain='{Environment.MachineName}',Name='Administratoren'\"");

            foreach (var o in searcher.Get())
            {
                using var obj = (ManagementObject)o;
                string? part = obj["PartComponent"]?.ToString() ?? "";
                int idx = part.LastIndexOf("Name=\"", StringComparison.Ordinal);
                if (idx >= 0)
                {
                    int start = idx + 6;
                    int end = part.IndexOf('"', start);
                    if (end > start)
                        members.Add(part[start..end]);
                }
            }
        }
        catch
        {
            // ignorieren
        }
        return members;
    }
}
