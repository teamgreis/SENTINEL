using System.Globalization;
using System.Text;

namespace Sentinel.Core.Reporting;

/// <summary>
/// Exportiert einen Bericht als lokale Textdatei. Keine Cloud, keine Telemetrie.
/// </summary>
public static class ReportExporter
{
    public static string ToPlainText(ScanReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("SENTINEL — Sicherheitsbericht");
        sb.AppendLine("Protect. Detect. Understand.");
        sb.AppendLine();
        sb.AppendLine($"Erstellt: {report.FinishedAt.ToLocalTime():dd.MM.yyyy HH:mm:ss}");
        sb.AppendLine($"Prüfdauer: {(report.FinishedAt - report.StartedAt).TotalSeconds:F1} s");
        sb.AppendLine();
        sb.AppendLine($"Gesamt-Score: {report.Score.Value}/100 ({report.Score.Grade})");
        sb.AppendLine($"Bewertet: {report.Score.Passed} bestanden, {report.Score.Warnings} Warnungen, " +
                      $"{report.Score.Failed} nicht bestanden, {report.Score.Unknown} unklar, {report.Score.Info} Infos");
        sb.AppendLine();
        sb.AppendLine("HINWEIS: Dieser Score ist eine Orientierung aus dokumentierten Einzelprüfungen.");
        sb.AppendLine("Er ist keine Garantie, dass dieses System sicher ist, und kann unbekannte Risiken übersehen.");
        sb.AppendLine(new string('─', 70));
        sb.AppendLine();

        foreach (var r in report.Results)
        {
            sb.AppendLine($"[{StatusIcon(r.Status)}] {r.Title}");
            sb.AppendLine($"    Befund: {r.Detail}");
            sb.AppendLine($"    Bedeutung: {r.Explanation}");
            if (r.RecommendedActions.Count > 0)
            {
                sb.AppendLine("    Nächste Schritte:");
                foreach (var a in r.RecommendedActions)
                    sb.AppendLine($"      • {a}");
            }
            if (r.Limitations is { Length: > 0 })
                sb.AppendLine($"    Grenzen: {r.Limitations}");
            if (r.Source is { Length: > 0 })
                sb.AppendLine($"    Quelle: {r.Source}");
            sb.AppendLine($"    Geprüft: {r.CheckedAt.ToLocalTime():HH:mm:ss} | Gewichtung: {r.Weight}");
            sb.AppendLine();
        }

        sb.AppendLine(new string('─', 70));
        sb.AppendLine("SENTINEL — Konzeptsoftware. Keine Sicherheitszertifizierung.");
        return sb.ToString();
    }

    public static async Task SaveAsync(ScanReport report, string path, CancellationToken ct = default)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        await File.WriteAllTextAsync(path, ToPlainText(report), Encoding.UTF8, ct).ConfigureAwait(false);
    }

    /// <summary>Reiner Text-Export als String (für HTML-Fallback und Tests).</summary>
    public static string ToText(ScanReport report) => ToPlainText(report);

    private static string StatusIcon(Checks.CheckStatus status) => status switch
    {
        Checks.CheckStatus.Pass => "OK",
        Checks.CheckStatus.Warning => "WARNUNG",
        Checks.CheckStatus.Fail => "PROBLEM",
        Checks.CheckStatus.Unknown => "UNKLAR",
        _ => "INFO"
    };
}
