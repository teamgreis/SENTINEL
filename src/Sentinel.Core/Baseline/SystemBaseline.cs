using System.Text.Json;

namespace Sentinel.Core.Baseline;

/// <summary>
/// Ein „gelerntes" Systemprofil: Welche Benutzer, Dienste, Autostarts,
/// Netzwerkfreigaben und geplanten Aufgaben existieren „normalerweise"?
/// Abweichungen davon sind ein starkes Manipulations-Signal.
/// </summary>
public sealed class SystemBaseline
{
    public DateTimeOffset CapturedAt { get; init; } = DateTimeOffset.UtcNow;
    public string? MachineName { get; init; }

    /// <summary>Lokale Benutzerkonten (Name → aktiv?).</summary>
    public Dictionary<string, bool> LocalUsers { get; init; } = new();

    /// <summary>Administratoren-Gruppe (Namen).</summary>
    public HashSet<string> Administrators { get; init; } = new();

    /// <summary>Laufende bzw. konfigurierte Dienste (Name → Starttyp).</summary>
    public Dictionary<string, string> Services { get; init; } = new();

    /// <summary>Autostart-Einträge (HKLM/HKCU Run): Name → Pfad.</summary>
    public Dictionary<string, string> AutostartEntries { get; init; } = new();

    /// <summary>Netzwerkfreigaben.</summary>
    public HashSet<string> NetworkShares { get; init; } = new();

    /// <summary>Geplante Aufgaben, die nicht Microsoft-Standard sind.</summary>
    public Dictionary<string, string> ScheduledTasks { get; init; } = new();

    /// <summary>Windows-Firewall-Regeln (Anzeigename → Aktion).</summary>
    public Dictionary<string, string> FirewallRules { get; init; } = new();

    /// <summary>Installierte Programme (nur zur Anzeige/Historie).</summary>
    public HashSet<string> InstalledPrograms { get; init; } = new();

    public string ToJson() => JsonSerializer.Serialize(new BaselineDto
    {
        CapturedAt = CapturedAt,
        MachineName = MachineName,
        LocalUsers = LocalUsers,
        Administrators = Administrators,
        Services = Services,
        AutostartEntries = AutostartEntries,
        NetworkShares = NetworkShares,
        ScheduledTasks = ScheduledTasks,
        FirewallRules = FirewallRules,
        InstalledPrograms = InstalledPrograms
    }, BaselineJson.Options);

    public static SystemBaseline? FromJson(string json)
    {
        try
        {
            var dto = JsonSerializer.Deserialize<BaselineDto>(json, BaselineJson.Options);
            if (dto is null) return null;
            return new SystemBaseline
            {
                CapturedAt = dto.CapturedAt,
                MachineName = dto.MachineName,
                LocalUsers = dto.LocalUsers ?? new(),
                Administrators = dto.Administrators ?? new(),
                Services = dto.Services ?? new(),
                AutostartEntries = dto.AutostartEntries ?? new(),
                NetworkShares = dto.NetworkShares ?? new(),
                ScheduledTasks = dto.ScheduledTasks ?? new(),
                FirewallRules = dto.FirewallRules ?? new(),
                InstalledPrograms = dto.InstalledPrograms ?? new()
            };
        }
        catch
        {
            return null;
        }
    }

    private sealed class BaselineDto
    {
        public DateTimeOffset CapturedAt { get; set; }
        public string? MachineName { get; set; }
        public Dictionary<string, bool>? LocalUsers { get; set; }
        public HashSet<string>? Administrators { get; set; }
        public Dictionary<string, string>? Services { get; set; }
        public Dictionary<string, string>? AutostartEntries { get; set; }
        public HashSet<string>? NetworkShares { get; set; }
        public Dictionary<string, string>? ScheduledTasks { get; set; }
        public Dictionary<string, string>? FirewallRules { get; set; }
        public HashSet<string>? InstalledPrograms { get; set; }
    }

    internal static class BaselineJson
    {
        public static readonly JsonSerializerOptions Options = new() { WriteIndented = true };
    }
}

/// <summary>Art einer Baseline-Abweichung.</summary>
public enum DeviationType
{
    NewUser,
    RemovedUser,
    NewAdmin,
    NewAutostart,
    RemovedAutostart,
    ChangedAutostart,
    NewService,
    RemovedService,
    ChangedServiceStartType,
    NewShare,
    RemovedShare,
    NewScheduledTask,
    RemovedScheduledTask,
    NewFirewallRule,
    RemovedFirewallRule
}

/// <summary>Eine erkannte Abweichung vom gelernten Normalzustand.</summary>
public sealed record BaselineDeviation
{
    public required DeviationType Type { get; init; }
    public required string Item { get; init; }
    public string? Detail { get; init; }

    /// <summary>Wie verdächtig ist das? Höher = eher manipulationsrelevant.</summary>
    public int Suspicion { get; init; }

    public string Describe() => Type switch
    {
        DeviationType.NewUser => $"Neues Benutzerkonto: {Item}",
        DeviationType.RemovedUser => $"Benutzerkonto entfernt: {Item}",
        DeviationType.NewAdmin => $"Neues Administratorkonto: {Item}",
        DeviationType.NewAutostart => $"Neuer Autostart-Eintrag: {Item}",
        DeviationType.RemovedAutostart => $"Autostart-Eintrag entfernt: {Item}",
        DeviationType.ChangedAutostart => $"Autostart geändert: {Item}",
        DeviationType.NewService => $"Neuer Dienst: {Item}",
        DeviationType.RemovedService => $"Dienst entfernt: {Item}",
        DeviationType.ChangedServiceStartType => $"Dienst-Starttyp geändert: {Item}",
        DeviationType.NewShare => $"Neue Netzwerkfreigabe: {Item}",
        DeviationType.RemovedShare => $"Freigabe entfernt: {Item}",
        DeviationType.NewScheduledTask => $"Neue geplante Aufgabe: {Item}",
        DeviationType.RemovedScheduledTask => $"Geplante Aufgabe entfernt: {Item}",
        DeviationType.NewFirewallRule => $"Neue Firewall-Regel: {Item}",
        DeviationType.RemovedFirewallRule => $"Firewall-Regel entfernt: {Item}",
        _ => Item
    };
}

/// <summary>Ergebnis eines Baseline-Vergleichs.</summary>
public sealed record BaselineComparison
{
    public IReadOnlyList<BaselineDeviation> Deviations { get; init; } = Array.Empty<BaselineDeviation>();

    public bool HasDeviations => Deviations.Count > 0;

    public int MaxSuspicion => Deviations.Count > 0 ? Deviations.Max(d => d.Suspicion) : 0;

    /// <summary>Nur die auffälligen Abweichungen.</summary>
    public IEnumerable<BaselineDeviation> Notable =>
        Deviations.Where(d => d.Suspicion >= 5).OrderByDescending(d => d.Suspicion);
}

/// <summary>
/// Vergleicht zwei Baselines. Reine Logik – testbar ohne Windows.
/// </summary>
public static class BaselineComparer
{
    public static BaselineComparison Compare(SystemBaseline baseline, SystemBaseline current)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(current);

        var deviations = new List<BaselineDeviation>();

        // Benutzer
        foreach (var user in current.LocalUsers.Keys)
        {
            if (!baseline.LocalUsers.ContainsKey(user))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.NewUser, Item = user, Suspicion = 6
                });
        }
        foreach (var user in baseline.LocalUsers.Keys)
        {
            if (!current.LocalUsers.ContainsKey(user))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.RemovedUser, Item = user, Suspicion = 4
                });
        }

        // Admins – ein neuer Admin ist hochverdächtig
        foreach (var admin in current.Administrators)
        {
            if (!baseline.Administrators.Contains(admin))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.NewAdmin, Item = admin, Suspicion = 9
                });
        }

        // Dienste
        foreach (var (name, startType) in current.Services)
        {
            if (!baseline.Services.ContainsKey(name))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.NewService, Item = name,
                    Detail = $"Starttyp: {startType}", Suspicion = 7
                });
            else if (!string.Equals(baseline.Services[name], startType, StringComparison.OrdinalIgnoreCase))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.ChangedServiceStartType, Item = name,
                    Detail = $"War: {baseline.Services[name]}, jetzt: {startType}", Suspicion = 5
                });
        }
        foreach (var name in baseline.Services.Keys)
        {
            if (!current.Services.ContainsKey(name))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.RemovedService, Item = name, Suspicion = 3
                });
        }

        // Autostart – klassische Persistenz-Stelle
        foreach (var (name, path) in current.AutostartEntries)
        {
            if (!baseline.AutostartEntries.ContainsKey(name))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.NewAutostart, Item = name,
                    Detail = path, Suspicion = 8
                });
            else if (!string.Equals(baseline.AutostartEntries[name], path, StringComparison.OrdinalIgnoreCase))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.ChangedAutostart, Item = name,
                    Detail = $"War: {baseline.AutostartEntries[name]}, jetzt: {path}", Suspicion = 8
                });
        }
        foreach (var name in baseline.AutostartEntries.Keys)
        {
            if (!current.AutostartEntries.ContainsKey(name))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.RemovedAutostart, Item = name, Suspicion = 3
                });
        }

        // Freigaben
        foreach (var share in current.NetworkShares)
        {
            if (!baseline.NetworkShares.Contains(share))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.NewShare, Item = share, Suspicion = 7
                });
        }
        foreach (var share in baseline.NetworkShares)
        {
            if (!current.NetworkShares.Contains(share))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.RemovedShare, Item = share, Suspicion = 2
                });
        }

        // Geplante Aufgaben
        foreach (var task in current.ScheduledTasks.Keys)
        {
            if (!baseline.ScheduledTasks.ContainsKey(task))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.NewScheduledTask, Item = task,
                    Detail = current.ScheduledTasks[task], Suspicion = 7
                });
        }
        foreach (var task in baseline.ScheduledTasks.Keys)
        {
            if (!current.ScheduledTasks.ContainsKey(task))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.RemovedScheduledTask, Item = task, Suspicion = 3
                });
        }

        // Firewall-Regeln
        foreach (var rule in current.FirewallRules.Keys)
        {
            if (!baseline.FirewallRules.ContainsKey(rule))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.NewFirewallRule, Item = rule,
                    Detail = current.FirewallRules[rule], Suspicion = 6
                });
        }
        foreach (var rule in baseline.FirewallRules.Keys)
        {
            if (!current.FirewallRules.ContainsKey(rule))
                deviations.Add(new BaselineDeviation
                {
                    Type = DeviationType.RemovedFirewallRule, Item = rule, Suspicion = 6
                });
        }

        return new BaselineComparison { Deviations = deviations };
    }
}
