namespace Sentinel.Core.Checks;

/// <summary>Ergebnisstatus einer einzelnen Prüfung.</summary>
public enum CheckStatus
{
    /// <summary>Prüfung bestanden / Konfiguration empfohlen.</summary>
    Pass,

    /// <summary>Prüfung nicht bestanden oder Konfiguration nicht empfohlen.</summary>
    Fail,

    /// <summary>Teilweise erfüllt oder Konfiguration nicht eindeutig bewertbar.</summary>
    Warning,

    /// <summary>Status konnte nicht ermittelt werden (z. B. fehlende Rechte).</summary>
    Unknown,

    /// <summary>Reiner Informationspunkt, keine Bewertung.</summary>
    Info
}

/// <summary>Ein dokumentiertes Einzelergebnis einer Prüfung.</summary>
public sealed record CheckResult
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required CheckStatus Status { get; init; }
    public required string Detail { get; init; }

    /// <summary>Was dieses Ergebnis für den Nutzer bedeutet – einfache Sprache.</summary>
    public required string Explanation { get; init; }

    /// <summary>Gewichtung im Score – dokumentiert jedes Kriterium nachvollziehbar.</summary>
    public CheckWeight Weight { get; init; } = CheckWeight.Normal;

    /// <summary>Konkrete, manuelle Handlungsschritte. Leer, wenn nichts zu tun ist.</summary>
    public IReadOnlyList<string> RecommendedActions { get; init; } = Array.Empty<string>();

    /// <summary>Zeitpunkt der Prüfung (UTC).</summary>
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Einschränkungen der Prüfung – was sie NICHT aussagt.</summary>
    public string? Limitations { get; init; }

    /// <summary>Quelle/Prüfmethode zur Nachvollziehbarkeit.</summary>
    public string? Source { get; init; }

    public bool IsSatisfactory => Status == CheckStatus.Pass || Status == CheckStatus.Info;
}

/// <summary>Gewichtung eines Checks im Score (1 = niedrig, 3 = hoch).</summary>
public enum CheckWeight { Low = 1, Normal = 2, High = 3 }

/// <summary>Definition eines ausführbaren Checks.</summary>
public interface ICheck
{
    string Id { get; }
    string Title { get; }
    CheckWeight Weight { get; }
    string Description { get; }

    /// <summary>Führt die Prüfung aus. Darf nicht schreiben – read-only.</summary>
    Task<CheckResult> RunAsync(CancellationToken ct = default);
}
