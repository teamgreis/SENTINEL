using Sentinel.Core.Checks;

namespace Sentinel.Core.Scoring;

/// <summary>
/// Nachvollziehbarer Sicherheits-Score. Keine Garantie – nur Orientierung
/// aus dokumentierten, reproduzierbaren Einzelkriterien.
/// </summary>
public sealed record SecurityScore
{
    /// <summary>0–100. Gewichteter Erfüllungsgrad der bewerteten Kriterien.</summary>
    public int Value { get; init; }

    /// <summary>Menschlich lesbare Einordnung.</summary>
    public ScoreGrade Grade { get; init; }

    public int Passed { get; init; }
    public int Failed { get; init; }
    public int Warnings { get; init; }
    public int Unknown { get; init; }
    public int Info { get; init; }

    /// <summary>Anzahl der tatsächlich bewerteten Kriterien (Pass/Fail/Warning).</summary>
    public int Graded { get; init; }

    /// <summary>Die Einzelaufschlüsselung – Score ohne diese ist nicht nachvollziehbar.</summary>
    public IReadOnlyList<ScoreContribution> Contributions { get; init; } = Array.Empty<ScoreContribution>();

    /// <summary>Erreichte Punkte über alle bewerteten Checks.</summary>
    public int EarnedPoints { get; init; }

    /// <summary>Maximal mögliche Punkte über alle bewerteten Checks.</summary>
    public int MaxPoints { get; init; }
}

public sealed record ScoreContribution
{
    public required string CheckId { get; init; }
    public required string Title { get; init; }
    public required CheckStatus Status { get; init; }
    public CheckWeight Weight { get; init; }
    public int Earned { get; init; }
    public int Max { get; init; }
}

public enum ScoreGrade
{
    Gut,
    Verbesserungsbedarf,
    Kritisch,
    Unbekannt
}

/// <summary>Berechnet den Score aus dokumentierten Einzelergebnissen.</summary>
public static class ScoreCalculator
{
    /// <summary>
    /// Gewichteter Score. Regeln (bewusst konservativ und transparent):
    /// - Pass  = volle Punkte
    /// - Fail  = 0 Punkte
    /// - Warning = halbe Punkte
    /// - Info  = wird NICHT bewertet (Informationspunkt)
    /// - Unknown = wird NICHT bewertet (nicht bewertbar, aus der Wertung genommen)
    /// </summary>
    public static SecurityScore Calculate(IReadOnlyList<CheckResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);

        var contributions = new List<ScoreContribution>();
        int passed = 0, failed = 0, warnings = 0, unknown = 0, info = 0, graded = 0;
        int earnedTotal = 0, maxTotal = 0;

        foreach (var r in results)
        {
            int max = (int)r.Weight * 10;
            int earned = r.Status switch
            {
                CheckStatus.Pass => max,
                CheckStatus.Warning => max / 2,
                _ => 0
            };

            if (r.Status is not (CheckStatus.Info or CheckStatus.Unknown))
            {
                graded++;
                maxTotal += max;
                earnedTotal += earned;
                switch (r.Status)
                {
                    case CheckStatus.Pass: passed++; break;
                    case CheckStatus.Warning: warnings++; break;
                    default: failed++; break;
                }
            }
            else if (r.Status == CheckStatus.Unknown) unknown++;
            else info++;

            contributions.Add(new ScoreContribution
            {
                CheckId = r.Id,
                Title = r.Title,
                Status = r.Status,
                Weight = r.Weight,
                Earned = r.Status is CheckStatus.Info or CheckStatus.Unknown ? 0 : earned,
                Max = r.Status is CheckStatus.Info or CheckStatus.Unknown ? 0 : max
            });
        }

        int percent = maxTotal > 0 ? (int)Math.Round(100.0 * earnedTotal / maxTotal) : 0;

        return new SecurityScore
        {
            Value = percent,
            Grade = maxTotal > 0 ? GradeFor(percent) : ScoreGrade.Unbekannt,
            Passed = passed,
            Failed = failed,
            Warnings = warnings,
            Unknown = unknown,
            Info = info,
            Graded = graded,
            EarnedPoints = earnedTotal,
            MaxPoints = maxTotal,
            Contributions = contributions
        };
    }

    private static ScoreGrade GradeFor(int percent) => percent switch
    {
        >= 80 => ScoreGrade.Gut,
        >= 50 => ScoreGrade.Verbesserungsbedarf,
        _ => ScoreGrade.Kritisch
    };
}
