namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Führt Abfragen gegen mehrere Datenbanken parallel aus,
/// fasst die Ergebnisse zu einem Gesamturteil zusammen.
/// Beachtet: Caching (vermeidet Doppelabfragen), Rate-Limiting (VirusTotal 4/Min),
/// Key-Verwaltung (nur geladene Keys werden genutzt), Fehlertoleranz
/// (eine ausgefallene Datenbank blockiert nicht die anderen).
/// </summary>
public sealed class ThreatAggregator
{
    private readonly IReadOnlyList<IThreatProvider> _providers;
    private readonly IResultCache? _cache;
    private readonly IRateLimiter? _rateLimiter;

    public ThreatAggregator(IEnumerable<IThreatProvider> providers,
        IResultCache? cache = null, IRateLimiter? rateLimiter = null)
    {
        _providers = providers.ToList();
        _cache = cache;
        _rateLimiter = rateLimiter;
    }

    /// <summary>Alle registrierten Provider.</summary>
    public IReadOnlyList<IThreatProvider> Providers => _providers;

    /// <summary>Provider, die diesen Abfragetyp unterstützen und (falls nötig) einen Key haben.</summary>
    public IReadOnlyList<IThreatProvider> EligibleFor(ThreatQuery query, Func<string, string?> keyProvider)
    {
        return _providers
            .Where(p => p.SupportedKinds.Contains(query.Kind))
            .Where(p => !p.RequiresApiKey || !string.IsNullOrWhiteSpace(keyProvider(p.Id)))
            .ToList();
    }

    /// <summary>
    /// Fragt alle geeigneten Datenbanken ab (parallel) und liefert das Gesamturteil.
    /// </summary>
    public async Task<AggregatedVerdict> CheckAsync(
        ThreatQuery query,
        Func<string, string?> keyProvider,
        Func<string, bool>? isEnabled = null,
        CancellationToken ct = default)
    {
        var eligible = EligibleFor(query, keyProvider)
            .Where(p => isEnabled?.Invoke(p.Id) ?? true)
            .ToList();

        var tasks = eligible.Select(async provider =>
        {
            // Cache?
            if (_cache is not null &&
                _cache.TryGet(query, provider.Id, out var cached) && cached is not null)
                return cached;

            // Rate-Limit?
            if (_rateLimiter is not null && !_rateLimiter.TryAcquire(provider.Id))
            {
                return new ProviderOutcome
                {
                    ProviderId = provider.Id, ProviderName = provider.Name,
                    QuerySucceeded = false,
                    Error = "Rate-Limit erreicht – später erneut versuchen.",
                    Latency = TimeSpan.Zero
                };
            }

            var outcome = await SafeExecute(provider, query, keyProvider(provider.Id), ct).ConfigureAwait(false);

            // Nur erfolgreiche Treffer cachen (Negativ-Ergebnisse kurz, Treffer länger)
            if (_cache is not null && outcome.QuerySucceeded)
                _cache.Set(query, provider.Id, outcome, outcome.IsThreat
                    ? TimeSpan.FromHours(1)
                    : TimeSpan.FromMinutes(5));

            return outcome;
        });

        var outcomes = (await Task.WhenAll(tasks).ConfigureAwait(false)).ToList();

        int queried = outcomes.Count;
        int flagged = outcomes.Count(o => o.IsThreat);
        int successful = outcomes.Count(o => o.QuerySucceeded);

        // Konfidenz: Anteil der meldenden an den erfolgreichen Abfragen (0 wenn keine Erfolge)
        int confidence = successful > 0 ? (int)Math.Round(100.0 * flagged / successful) : 0;

        return new AggregatedVerdict
        {
            Query = query,
            Outcomes = outcomes,
            ProvidersQueried = queried,
            ProvidersFlagged = flagged,
            Confidence = confidence
        };
    }

    /// <summary>
    /// Fängt Ausnahmen eines Providers, damit ein Ausfall nicht die gesamte Abfrage killt.
    /// </summary>
    private static async Task<ProviderOutcome> SafeExecute(IThreatProvider provider, ThreatQuery query,
        string? apiKey, CancellationToken ct)
    {
        var sw = global::System.Diagnostics.Stopwatch.StartNew();
        try
        {
            return await provider.QueryAsync(query, apiKey, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new ProviderOutcome
            {
                ProviderId = provider.Id,
                ProviderName = provider.Name,
                QuerySucceeded = false,
                Error = ex.Message,
                Latency = sw.Elapsed
            };
        }
    }
}

public interface IResultCache
{
    bool TryGet(ThreatQuery query, string providerId, out ProviderOutcome? outcome);
    void Set(ThreatQuery query, string providerId, ProviderOutcome outcome, TimeSpan ttl);
    void Clear();
}

/// <summary>Einfacher In-Memory-Cache mit TTL.</summary>
public sealed class MemoryResultCache : IResultCache
{
    private readonly Dictionary<string, (ProviderOutcome Outcome, DateTimeOffset ExpiresAt)> _entries = new();
    private readonly object _lock = new();

    public bool TryGet(ThreatQuery query, string providerId, out ProviderOutcome? outcome)
    {
        lock (_lock)
        {
            string key = BuildKey(query, providerId);
            if (_entries.TryGetValue(key, out var entry) && entry.ExpiresAt > DateTimeOffset.UtcNow)
            {
                outcome = entry.Outcome;
                return true;
            }

            _entries.Remove(key);
            outcome = null;
            return false;
        }
    }

    public void Set(ThreatQuery query, string providerId, ProviderOutcome outcome, TimeSpan ttl)
    {
        lock (_lock)
        {
            _entries[BuildKey(query, providerId)] = (outcome, DateTimeOffset.UtcNow + ttl);
        }
    }

    public void Clear()
    {
        lock (_lock) { _entries.Clear(); }
    }

    private static string BuildKey(ThreatQuery query, string providerId) => $"{providerId}|{query.Kind}|{query.Value.ToLowerInvariant()}";
}

public interface IRateLimiter
{
    bool TryAcquire(string providerId);
    void Reset(string providerId);
}

/// <summary>
/// Pro-Provider-Rate-Limiter: erlaubt max. N Abfragen pro Minute.
/// VirusTotal (frei): 4/Min. Andere: 10/Min Standard.
/// </summary>
public sealed class PerProviderRateLimiter : IRateLimiter
{
    private readonly Dictionary<string, Queue<DateTimeOffset>> _hits = new();
    private readonly Dictionary<string, int> _limits;
    private readonly object _lock = new();

    public PerProviderRateLimiter(Dictionary<string, int>? limits = null)
    {
        _limits = limits ?? new Dictionary<string, int>
        {
            ["virustotal"] = 4,
            ["safebrowsing"] = 30,
            ["otx"] = 10,
            ["threatfox"] = 20
        };
    }

    public bool TryAcquire(string providerId)
    {
        int limit = _limits.TryGetValue(providerId, out var l) ? l : 10;

        lock (_lock)
        {
            if (!_hits.TryGetValue(providerId, out var queue))
            {
                queue = new Queue<DateTimeOffset>();
                _hits[providerId] = queue;
            }

            var cutoff = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(1);
            while (queue.Count > 0 && queue.Peek() < cutoff)
                queue.Dequeue();

            if (queue.Count >= limit)
                return false;

            queue.Enqueue(DateTimeOffset.UtcNow);
            return true;
        }
    }

    public void Reset(string providerId)
    {
        lock (_lock)
        {
            _hits.Remove(providerId);
        }
    }
}
