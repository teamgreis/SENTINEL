using System.Text.Json;
using Sentinel.Core.Scoring;

namespace Sentinel.Core.Reporting;

/// <summary>Ein gespeicherter Verlaufseintrag (Score-Verlauf).</summary>
public sealed record HistoryEntry
{
    public DateTimeOffset Timestamp { get; init; }
    public int Score { get; init; }
    public string Grade { get; init; } = string.Empty;
    public int Passed { get; init; }
    public int Warnings { get; init; }
    public int Failed { get; init; }
    public int Unknown { get; init; }
}

/// <summary>
/// Speichert den Score-Verlauf als lokale JSON-Datei. Keine Cloud, keine Telemetrie.
/// </summary>
public sealed class HistoryStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    private readonly string _filePath;

    public HistoryStore(string filePath)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
    }

    public IReadOnlyList<HistoryEntry> Load()
    {
        try
        {
            if (!File.Exists(_filePath)) return Array.Empty<HistoryEntry>();
            var json = File.ReadAllText(_filePath);
            return JsonSerializer.Deserialize<List<HistoryEntry>>(json) ?? new List<HistoryEntry>();
        }
        catch
        {
            return Array.Empty<HistoryEntry>();
        }
    }

    public void Append(SecurityScore score)
    {
        ArgumentNullException.ThrowIfNull(score);

        var entries = Load().ToList();
        entries.Add(new HistoryEntry
        {
            Timestamp = DateTimeOffset.UtcNow,
            Score = score.Value,
            Grade = score.Grade.ToString(),
            Passed = score.Passed,
            Warnings = score.Warnings,
            Failed = score.Failed,
            Unknown = score.Unknown
        });

        // Maximal 100 Einträge behalten
        if (entries.Count > 100)
            entries = entries.Skip(entries.Count - 100).ToList();

        var dir = Path.GetDirectoryName(Path.GetFullPath(_filePath));
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        File.WriteAllText(_filePath, JsonSerializer.Serialize(entries, Options));
    }

    public void Clear()
    {
        if (File.Exists(_filePath)) File.Delete(_filePath);
    }
}
