using System.Text;
using Sentinel.Core.Checks;
using Sentinel.Core.Scoring;
using SB = global::System.Text.StringBuilder;

namespace Sentinel.Core.Reporting;

/// <summary>
/// Erzeugt einen ausführlichen HTML-Bericht (lokale Datei, kein Upload).
/// Erweitert den reinen Text-Export um Struktur und Lesbarkeit.
/// </summary>
public static class HtmlReportExporter
{
    public static string Render(ScanReport report)
    {
        var sb = new SB();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang='de'><head><meta charset='utf-8'>");
        sb.AppendLine($"<title>SENTINEL-Bericht {report.FinishedAt:yyyy-MM-dd}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body{font-family:Segoe UI,sans-serif;background:#0f0d17;color:#e6e4f0;max-width:900px;margin:0 auto;padding:32px}");
        sb.AppendLine("h1{font-weight:300;color:#fff}");
        sb.AppendLine(".score{font-size:56px;font-weight:200}");
        sb.AppendLine(".good{color:#4ade80}.warn{color:#fbbf24}.bad{color:#f87171}");
        sb.AppendLine(".card{background:#1a1726;border-radius:12px;padding:16px;margin:12px 0;border-left:3px solid #444}");
        sb.AppendLine(".card.good{border-left-color:#4ade80}.card.warn{border-left-color:#fbbf24}.card.bad{border-left-color:#f87171}");
        sb.AppendLine(".title{font-weight:600;font-size:15px;color:#fff}");
        sb.AppendLine(".detail{color:#b8b4cc;font-size:13px;margin-top:4px}");
        sb.AppendLine(".meta{color:#6f6a85;font-size:11px;margin-top:8px}");
        sb.AppendLine(".eyebrow{text-transform:uppercase;font-size:11px;letter-spacing:1px;color:#8b86a3;margin:24px 0 8px}");
        sb.AppendLine("ul{color:#b8b4cc;font-size:12px;margin:4px 0 0 16px;padding:0}");
        sb.AppendLine("</style></head><body>");

        // Kopf
        sb.AppendLine($"<h1>SENTINEL — Sicherheitsbericht</h1>");
        sb.AppendLine($"<p style='color:#8b86a3;font-size:12px'>Erstellt {report.FinishedAt.ToLocalTime():dd.MM.yyyy HH:mm} · " +
                      $"© Felix Greis (Alias: Elian) · Version {Core.Branding.FullVersion}</p>");

        // Score
        string gradeClass = report.Score.Grade switch
        {
            ScoreGrade.Gut => "good",
            ScoreGrade.Verbesserungsbedarf => "warn",
            ScoreGrade.Kritisch => "bad",
            _ => ""
        };
        sb.AppendLine($"<div class='score {gradeClass}'>{report.Score.Value}</div>");
        sb.AppendLine($"<div style='color:#8b86a3;margin-bottom:24px'>von 100 · {report.Score.Grade}</div>");
        sb.AppendLine($"<p style='color:#b8b4cc;font-size:13px'>Bewertete Prüfungen: {report.Score.Graded} — " +
                      $"{report.Score.Passed} bestanden, {report.Score.Warnings} Hinweis, " +
                      $"{report.Score.Failed} nicht bestanden, {report.Score.Unknown} unklar.</p>");

        // Ergebnisse
        foreach (var group in report.Results.GroupBy(r => r.Id.Split('.')[0]).OrderBy(g => g.Key))
        {
            sb.AppendLine($"<div class='eyebrow'>{Escape(group.Key)}</div>");
            foreach (var r in group.OrderByDescending(r => r.Weight))
            {
                string cls = r.Status switch
                {
                    CheckStatus.Pass => "good",
                    CheckStatus.Warning => "warn",
                    CheckStatus.Fail => "bad",
                    _ => ""
                };
                sb.AppendLine($"<div class='card {cls}'>");
                sb.AppendLine($"<div class='title'>{Escape(r.Title)}</div>");
                sb.AppendLine($"<div class='detail'>{Escape(r.Detail)}</div>");

                if (r.RecommendedActions.Count > 0)
                {
                    sb.AppendLine("<ul>");
                    foreach (var a in r.RecommendedActions)
                        sb.AppendLine($"<li>{Escape(a)}</li>");
                    sb.AppendLine("</ul>");
                }

                sb.AppendLine($"<div class='meta'>Status: {r.Status} · Gewicht: {r.Weight} · Quelle: {Escape(r.Source ?? "—")}</div>");
                sb.AppendLine("</div>");
            }
        }

        // Fußnote
        sb.AppendLine("<div class='eyebrow'>Hinweis</div>");
        sb.AppendLine("<p style='color:#6f6a85;font-size:12px'>Alle Prüfungen liefen lokal. " +
                      "SENTINEL ist ein Analysewerkzeug, kein Ersatz für einen Virenscanner.</p>");

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    private static string Escape(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
}
