namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Eine Bedrohungs-Datenbank. Implementierungen sind reine Client-Logik,
/// testbar ohne echtes Netzwerk über <see cref="IHttpTransport"/>.
/// </summary>
public interface IThreatProvider
{
    string Id { get; }

    /// <summary>Anzeigename.</summary>
    string Name { get; }

    /// <summary>Kurze Beschreibung, was geprüft wird.</summary>
    string Description { get; }

    /// <summary>Braucht diese Datenbank einen API-Key?</summary>
    bool RequiresApiKey { get; }

    /// <summary>Welche Abfrage-Arten werden unterstützt?</summary>
    IReadOnlyList<ThreatKind> SupportedKinds { get; }

    /// <summary>Homepage/Registrierung für API-Keys.</summary>
    string InfoUrl { get; }

    /// <summary>Führt die Abfrage aus. apiKey darf null sein, wenn nicht benötigt.</summary>
    Task<ProviderOutcome> QueryAsync(ThreatQuery query, string? apiKey, CancellationToken ct = default);
}
