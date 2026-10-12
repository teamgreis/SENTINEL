namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Ergebnis einer Online-Bedrohungsprüfung.
/// Wichtig: „Clean" bedeutet NUR, dass die geprüfte Quelle nichts gefunden hat –
/// keine Garantie, dass eine Datei/URL harmlos ist.
/// </summary>
public sealed record ThreatIntelResult
{
    public required string Query { get; init; }

    /// <summary>true = in Datenbank als bösartig gelistet. false = nicht gelistet ODER Fehler.</summary>
    public bool IsKnownMalicious { get; init; }

    /// <summary>true = Abfrage wurde technisch erfolgreich durchgeführt.</summary>
    public bool QuerySucceeded { get; init; }

    /// <summary>Name/Signatur aus der Datenbank (falls gefunden).</summary>
    public string? Signature { get; init; }

    /// <summary>Dateityp (MalwareBazaar).</summary>
    public string? FileType { get; init; }

    /// <summary>Erstmals gesehen (MalwareBazaar).</summary>
    public string? FirstSeen { get; init; }

    /// <summary>Menschlich lesbare Zusammenfassung.</summary>
    public required string Summary { get; init; }

    /// <summary>Quelle der Information.</summary>
    public string? Source { get; init; }

    /// <summary>Fehlermeldung, falls die Abfrage scheiterte.</summary>
    public string? Error { get; init; }

    /// <summary>Wie viele Einträge die Datenbank für diese Abfrage kennt.</summary>
    public int DetectionCount { get; init; }

    public static ThreatIntelResult Listed(
        string query, string? signature, string? fileType, string? firstSeen, int count, string source) =>
        new()
        {
            Query = query,
            IsKnownMalicious = true,
            QuerySucceeded = true,
            Signature = signature,
            FileType = fileType,
            FirstSeen = firstSeen,
            DetectionCount = count,
            Summary = signature is { Length: > 0 }
                ? $"Diese Datei ist einer bekannten Schadsoftware zugeordnet: {signature}."
                : "Diese Datei ist in einer öffentlichen Malware-Datenbank gelistet.",
            Source = source
        };

    public static ThreatIntelResult NotListed(string query, string source) => new()
    {
        Query = query,
        IsKnownMalicious = false,
        QuerySucceeded = true,
        DetectionCount = 0,
        Summary = "Kein Eintrag in der geprüften Datenbank gefunden. Das ist keine Garantie, dass die Datei harmlos ist.",
        Source = source
    };

    public static ThreatIntelResult Failed(string query, string error, string source) => new()
    {
        Query = query,
        IsKnownMalicious = false,
        QuerySucceeded = false,
        Error = error,
        Summary = $"Online-Prüfung nicht möglich: {error}",
        Source = source
    };
}
