namespace Sentinel.Core.ThreatIntel;

/// <summary>Art des geprüften Objekts.</summary>
public enum ThreatKind
{
    Url,
    FileHash,
    IpAddress,
    Domain
}

/// <summary>Eine Abfrage an die Datenbanken.</summary>
public sealed record ThreatQuery(ThreatKind Kind, string Value)
{
    public override string ToString() => $"{Kind}:{Value}";
}

/// <summary>Ergebnis einer einzelnen Datenbank-Abfrage.</summary>
public sealed record ProviderOutcome
{
    public required string ProviderId { get; init; }
    public required string ProviderName { get; init; }

    /// <summary>true = als Bedrohung gelistet.</summary>
    public bool IsThreat { get; init; }

    /// <summary>true = Abfrage technisch durchgeführt (auch wenn nichts gefunden).</summary>
    public bool QuerySucceeded { get; init; }

    /// <summary>Kategorie/Typ aus der Datenbank (z. B. „botnet_c2\").</summary>
    public string? Category { get; init; }

    /// <summary>Zusätzliche Details.</summary>
    public string? Details { get; init; }

    /// <summary>Fehlermeldung bei Misserfolg.</summary>
    public string? Error { get; init; }

    /// <summary>Wie lange die Abfrage dauerte.</summary>
    public TimeSpan Latency { get; init; }

    /// <summary>Anzahl der Quellen in der Datenbank, die darauf hinweisen.</summary>
    public int DetectionCount { get; init; }
}

/// <summary>
/// Ergebnis über alle abgefragten Datenbanken.
/// </summary>
public sealed record AggregatedVerdict
{
    public required ThreatQuery Query { get; init; }
    public IReadOnlyList<ProviderOutcome> Outcomes { get; init; } = Array.Empty<ProviderOutcome>();

    /// <summary>Wie viele Datenbanken abgefragt wurden (erfolgreich oder nicht).</summary>
    public int ProvidersQueried { get; init; }

    /// <summary>Wie viele davon eine Bedrohung melden.</summary>
    public int ProvidersFlagged { get; init; }

    /// <summary>Mindestens eine Datenbank meldet eine Bedrohung.</summary>
    public bool AnyFlagged => ProvidersFlagged > 0;

    /// <summary>0–100: Anteil der meldenden Datenbanken an den erfolgreichen Abfragen.</summary>
    public int Confidence { get; init; }

    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Die erfolgreichen Ergebnisse (für Detailanzeige).</summary>
    public IEnumerable<ProviderOutcome> Successful => Outcomes.Where(o => o.QuerySucceeded);

    /// <summary>Die fehlgeschlagenen (für Detailanzeige).</summary>
    public IEnumerable<ProviderOutcome> Failed => Outcomes.Where(o => !o.QuerySucceeded);

    public string Summary
    {
        get
        {
            if (ProvidersQueried == 0)
                return "Keine Datenbank abgefragt.";

            if (ProvidersFlagged == 0)
                return $"Keine der {ProvidersQueried} abgefragten Datenbanken kennt diesen Eintrag. " +
                       "Das ist keine Garantie für Sicherheit – neue oder seltene Bedrohungen sind dort oft nicht gelistet.";

            var names = Successful.Where(o => o.IsThreat).Select(o => o.ProviderName).ToList();
            return $"⚠ {ProvidersFlagged} von {ProvidersQueried} Datenbanken melden eine Bedrohung " +
                   $"(Konfidenz {Confidence}%): {string.Join(", ", names)}.";
        }
    }

    public VerdictLevel Level => ProvidersFlagged switch
    {
        0 => ProvidersQueried > 0 ? VerdictLevel.Clean : VerdictLevel.Unknown,
        1 => VerdictLevel.Suspicious,
        _ => VerdictLevel.Dangerous
    };
}

public enum VerdictLevel
{
    Unknown,
    Clean,
    Suspicious,
    Dangerous
}
