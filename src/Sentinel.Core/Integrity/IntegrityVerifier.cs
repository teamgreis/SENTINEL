using System.Security.Cryptography;
using System.Text.Json;

namespace Sentinel.Core.Integrity;

/// <summary>Status einer einzelnen Datei im Integritätscheck.</summary>
public enum FileIntegrityStatus
{
    Ok,
    Modified,
    Missing,
    New
}

/// <summary>Ergebnis einer Datei-Prüfung.</summary>
public sealed record FileIntegrityResult
{
    public required string FileName { get; init; }
    public required FileIntegrityStatus Status { get; init; }
    public string? ExpectedHash { get; init; }
    public string? ActualHash { get; init; }
}

/// <summary>Gesamtergebnis der Selbstprüfung.</summary>
public sealed record IntegrityReport
{
    public IReadOnlyList<FileIntegrityResult> Files { get; init; } = Array.Empty<FileIntegrityResult>();
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;

    public bool IsIntact => Files.All(f => f.Status == FileIntegrityStatus.Ok);
    public bool HasModified => Files.Any(f => f.Status == FileIntegrityStatus.Modified);
    public bool HasMissing => Files.Any(f => f.Status == FileIntegrityStatus.Missing);
    public bool HasNew => Files.Any(f => f.Status == FileIntegrityStatus.New);

    public IEnumerable<FileIntegrityResult> Problems =>
        Files.Where(f => f.Status != FileIntegrityStatus.Ok);

    public string Summary => IsIntact
        ? $"Alle {Files.Count} Programmdateien unverändert."
        : $"{Problems.Count()} von {Files.Count} Dateien weichen vom erwarteten Zustand ab.";
}

/// <summary>
/// Erzeugt und prüft ein Signatur-Manifest der eigenen Programmdateien.
/// Erkennt Manipulation, Beschädigung und unbekannte Zusatzdateien.
/// </summary>
public static class IntegrityVerifier
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    private const string ManifestFileName = "integrity.manifest.json";

    /// <summary>Erzeugt ein Manifest aller relevanten Dateien im Programmordner.</summary>
    public static IntegrityManifest CreateManifest(string appDirectory, IEnumerable<string> fileNames)
    {
        ArgumentException.ThrowIfNullOrEmpty(appDirectory);

        var entries = new Dictionary<string, string>();
        foreach (var name in fileNames)
        {
            var path = Path.Combine(appDirectory, name);
            if (!File.Exists(path)) continue;
            entries[name] = ComputeFileHash(path);
        }

        return new IntegrityManifest
        {
            CreatedAt = DateTimeOffset.UtcNow,
            Entries = entries
        };
    }

    /// <summary>Prüft das aktuelle Verzeichnis gegen das gespeicherte Manifest.</summary>
    public static IntegrityReport Verify(string appDirectory, IntegrityManifest manifest)
    {
        ArgumentException.ThrowIfNullOrEmpty(appDirectory);
        ArgumentNullException.ThrowIfNull(manifest);

        var results = new List<FileIntegrityResult>();

        // Bekannte Dateien prüfen
        foreach (var (name, expected) in manifest.Entries)
        {
            var path = Path.Combine(appDirectory, name);

            if (!File.Exists(path))
            {
                results.Add(new FileIntegrityResult
                {
                    FileName = name, Status = FileIntegrityStatus.Missing, ExpectedHash = expected
                });
                continue;
            }

            string actual = ComputeFileHash(path);
            results.Add(new FileIntegrityResult
            {
                FileName = name,
                Status = actual.Equals(expected, StringComparison.OrdinalIgnoreCase)
                    ? FileIntegrityStatus.Ok
                    : FileIntegrityStatus.Modified,
                ExpectedHash = expected,
                ActualHash = actual
            });
        }

        // Neue, unbekannte ausführbare Dateien erkennen
        foreach (var extra in Directory.EnumerateFiles(appDirectory, "*.exe")
                     .Concat(Directory.EnumerateFiles(appDirectory, "*.dll"))
                     .Select(Path.GetFileName)
                     .Where(n => n is not null && !manifest.Entries.ContainsKey(n!))
                     .Distinct())
        {
            results.Add(new FileIntegrityResult
            {
                FileName = extra!,
                Status = FileIntegrityStatus.New,
                ActualHash = ComputeFileHash(Path.Combine(appDirectory, extra!))
            });
        }

        return new IntegrityReport { Files = results };
    }

    /// <summary>Speichert ein Manifest neben der App.</summary>
    public static void SaveManifest(string appDirectory, IntegrityManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var path = Path.Combine(appDirectory, ManifestFileName);
        File.WriteAllText(path, JsonSerializer.Serialize(manifest, Options));
    }

    /// <summary>Lädt ein gespeichertes Manifest.</summary>
    public static IntegrityManifest? LoadManifest(string appDirectory)
    {
        var path = Path.Combine(appDirectory, ManifestFileName);
        if (!File.Exists(path)) return null;

        try
        {
            var dto = JsonSerializer.Deserialize<ManifestDto>(File.ReadAllText(path));
            if (dto is null) return null;
            return new IntegrityManifest
            {
                CreatedAt = dto.CreatedAt,
                Entries = dto.Entries ?? new Dictionary<string, string>()
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>SHA-256 einer Datei.</summary>
    public static string ComputeFileHash(string path)
    {
        using var sha = SHA256.Create();
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
    }

    public static string ManifestFileNameConst => ManifestFileName;

    private sealed class ManifestDto
    {
        public DateTimeOffset CreatedAt { get; set; }
        public Dictionary<string, string>? Entries { get; set; }
    }
}

/// <summary>Signatur-Manifest: Dateiname → SHA-256.</summary>
public sealed class IntegrityManifest
{
    public DateTimeOffset CreatedAt { get; init; }
    public Dictionary<string, string> Entries { get; init; } = new();
}
