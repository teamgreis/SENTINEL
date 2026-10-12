using Sentinel.Core.Checks;

namespace Sentinel.Core.Reporting;

/// <summary>Protokolleintrag – Nachvollziehbarkeit der eigenen Aktionen.</summary>
public sealed record ActionLogEntry
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public required string Action { get; init; }
    public string? Detail { get; init; }
}

/// <summary>Vollständiges Ergebnis eines Prüfdurchlaufs.</summary>
public sealed record ScanReport
{
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset FinishedAt { get; init; }
    public IReadOnlyList<CheckResult> Results { get; init; } = Array.Empty<CheckResult>();
    public Scoring.SecurityScore Score { get; init; } = new();
}

/// <summary>Führt registrierte Checks aus und baut daraus den Bericht.</summary>
public sealed class ScanRunner
{
    private readonly IEnumerable<ICheck> _checks;
    private readonly List<ActionLogEntry> _log = new();

    public ScanRunner(IEnumerable<ICheck> checks)
    {
        _checks = checks ?? throw new ArgumentNullException(nameof(checks));
    }

    public IReadOnlyList<ActionLogEntry> Log => _log;

    public async Task<ScanReport> RunAsync(CancellationToken ct = default)
    {
        var started = DateTimeOffset.UtcNow;
        ct.ThrowIfCancellationRequested();
        var results = new List<CheckResult>();

        foreach (var check in _checks)
        {
            if (ct.IsCancellationRequested) break;

            try
            {
                var result = await check.RunAsync(ct).ConfigureAwait(false);
                results.Add(result);
                _log.Add(new ActionLogEntry
                {
                    Action = $"Check ausgeführt: {check.Title}",
                    Detail = $"Status: {result.Status}"
                });
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Ein fehlgeschlagener Check darf nicht den ganzen Scan killen.
                results.Add(new CheckResult
                {
                    Id = check.Id,
                    Title = check.Title,
                    Status = CheckStatus.Unknown,
                    Weight = check.Weight,
                    Detail = "Prüfung konnte nicht ausgeführt werden.",
                    Explanation = "Bei dieser Prüfung ist ein Fehler aufgetreten. Das sagt nichts über deine Sicherheit aus.",
                    Limitations = ex.Message
                });
                _log.Add(new ActionLogEntry
                {
                    Action = $"Check fehlgeschlagen: {check.Title}",
                    Detail = ex.Message
                });
            }
        }

        return new ScanReport
        {
            StartedAt = started,
            FinishedAt = DateTimeOffset.UtcNow,
            Results = results,
            Score = Scoring.ScoreCalculator.Calculate(results)
        };
    }
}
