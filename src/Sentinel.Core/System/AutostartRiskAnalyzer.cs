namespace Sentinel.Core.System;

/// <summary>
/// Parst die Autostart-Einträge und bewertet sie nach Risiko.
/// Reine Logik – testbar ohne Windows.
/// </summary>
public static class AutostartRiskAnalyzer
{
    /// <summary>Ein Autostart-Eintrag mit Risikobewertung.</summary>
    public sealed record AutostartEntry(string Name, string Command, int RiskScore, string RiskReason);

    /// <summary>
    /// Bewertet einen einzelnen Autostart-Befehl.
    /// Höherer Score = verdächtiger.
    /// </summary>
    public static AutostartEntry Analyze(string name, string command)
    {
        string cmd = command?.Trim() ?? "";
        string lower = cmd.ToLowerInvariant();
        int score = 0;
        var reasons = new List<string>();

        // Aus TEMP/AppData gestartet = klassische Malware-Persistenz
        if (lower.Contains("\\temp\\") || lower.Contains("\\appdata\\local\\temp"))
        {
            score += 8;
            reasons.Add("startet aus TEMP");
        }

        // PowerShell/WScript/CScript im Autostart = ungewöhnlich
        if (lower.Contains("powershell") || lower.Contains("wscript") || lower.Contains("cscript"))
        {
            score += 5;
            reasons.Add("Skript-Host");
        }

        // base64-Blob = verschleierter Code
        if (lower.Contains("-encodedcommand") || lower.Contains("base64") || lower.Contains("-e "))
        {
            score += 9;
            reasons.Add("verschleierter Code (base64)");
        }

        // Download-Cradle
        if (lower.Contains("downloadstring") || lower.Contains("invoke-webrequest") ||
            lower.Contains("iwr ") || lower.Contains("curl ") || lower.Contains("wget "))
        {
            score += 8;
            reasons.Add("lädt Code aus dem Netz");
        }

        // Registry-Run-Schlüssel manipulieren
        if (lower.Contains("reg add") || lower.Contains("new-itemproperty"))
        {
            score += 6;
            reasons.Add("ändert die Registrierung");
        }

        // Taskkill (Anti-Analyse)
        if (lower.Contains("taskkill") || lower.Contains("stop-process"))
        {
            score += 4;
            reasons.Add("beendet Prozesse");
        }

        return new AutostartEntry(
            name ?? "?",
            cmd,
            score,
            reasons.Count > 0 ? string.Join(", ", reasons) : "unauffällig");
    }

    /// <summary>Ab diesem Score gilt ein Eintrag als warnwürdig.</summary>
    public const int SuspicionThreshold = 5;
}
