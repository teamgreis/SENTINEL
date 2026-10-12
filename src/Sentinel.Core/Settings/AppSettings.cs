using System.Text.Json;

namespace Sentinel.Core.Settings;

/// <summary>Design-Themes (5 Designs).</summary>
public enum ThemeMode
{
    /// <summary>Sentinel Standard — dunkles Violett/Cyan.</summary>
    Dark,
    /// <summary>Midnight — tiefes Nachtblau.</summary>
    Midnight,
    /// <summary>DeepSpace — schwarz mit Neon-Grün.</summary>
    DeepSpace,
    /// <summary>Solarized — warmes Sepia/Dunkelbraun.</summary>
    Solarized,
    /// <summary>Mono — reines Schwarz/Weiß, maximaler Kontrast, farbfrei.</summary>
    Mono
}

/// <summary>Scan-Tiefe.</summary>
public enum ScanDepth
{
    Quick,
    Standard,
    Deep
}

/// <summary>Alle Nutzer-Einstellungen an einem Ort. Persistiert als JSON.</summary>
public sealed class AppSettings
{
    // ---- Erscheinungsbild ----
    public ThemeMode Theme { get; set; } = ThemeMode.Dark;
    public bool CompactMode { get; set; }
    public bool ShowExplanations { get; set; } = true;
    public bool ShowAdvancedDetails { get; set; }
    public double FontScale { get; set; } = 1.0;
    public bool AnimationsEnabled { get; set; } = true;
    public bool ColorBlindMode { get; set; }

    // ---- Verhalten ----
    public bool CheckOnStartup { get; set; } = true;
    public ScanDepth StartupScanDepth { get; set; } = ScanDepth.Quick;
    public bool RunAtWindowsStartup { get; set; }
    public bool MinimizeToTray { get; set; } = true;
    public bool ShowStartupNotification { get; set; } = true;
    public bool AutoExportReport { get; set; }
    public string? ReportFolder { get; set; }

    // ---- Prüfungen ----
    public bool IncludeInfoChecksInScore { get; set; } = true;
    public bool TreatWarningsAsFailures { get; set; }
    public int MinimumScoreForGoodGrade { get; set; } = 80;
    public bool RequireAdminForFullScan { get; set; } = true;
    public bool CheckUpdates { get; set; } = true;
    public bool CheckDefender { get; set; } = true;
    public bool CheckFirewall { get; set; } = true;
    public bool CheckAccounts { get; set; } = true;
    public bool CheckNetwork { get; set; } = true;
    public bool CheckStartup { get; set; } = true;
    public bool CheckSystemHardening { get; set; } = true;

    // ---- Online & Datenschutz ----
    public bool OnlineChecksEnabled { get; set; }
    public bool ShowOnlineDisclaimer { get; set; } = true;
    public bool ConfirmBeforeOnlineCheck { get; set; } = true;
    public bool TelemetryEnabled { get; set; } // bleibt false – keine Telemetrie

    // ---- Baseline & Verlauf ----
    public bool BaselineEnabled { get; set; } = true;
    public bool AutoUpdateBaseline { get; set; }
    public int BaselineAlertThreshold { get; set; } = 5;
    public bool KeepHistoryDays { get; set; } = true;
    public int HistoryRetentionDays { get; set; } = 90;
    public int MaxHistoryEntries { get; set; } = 100;

    // ---- Sicherheit der App ----
    public bool RequirePasswordOnStart { get; set; } = true;
    public bool LockAfterInactivity { get; set; } = true;
    public int LockAfterMinutes { get; set; } = 15;
    public bool IntegrityCheckOnStart { get; set; } = true;
    public bool BlockIfManipulated { get; set; } = true;
    public bool StartupCheckOnWindowsBoot { get; set; }
    public bool StartupCheckQuietMode { get; set; } = true;

    // ---- Updates ----
    public bool AutoCheckUpdates { get; set; } = true;
    public bool NotifyOnlyCriticalUpdates { get; set; }

    // ---- Export ----
    public bool IncludeHashInExport { get; set; } = true;
    public bool IncludeHistoryInExport { get; set; } = true;

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static AppSettings Load(string path)
    {
        try
        {
            if (!File.Exists(path)) return new AppSettings();
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<AppSettings>(json, Options) ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    public void Save(string path)
    {
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            File.WriteAllText(path, JsonSerializer.Serialize(this, Options));
        }
        catch
        {
            // Einstellungen speichern darf die App nie crashen
        }
    }

    /// <summary>Setzt alles auf Standard zurück.</summary>
    public void Reset()
    {
        var fresh = new AppSettings();
        foreach (var prop in GetType().GetProperties())
        {
            if (!prop.CanWrite) continue;
            prop.SetValue(this, prop.GetValue(fresh));
        }
    }

    /// <summary>Anzahl der konfigurierbaren Einstellungen (zur Anzeige).</summary>
    public static int SettingCount => typeof(AppSettings)
        .GetProperties()
        .Count(p => p.CanWrite);
}
