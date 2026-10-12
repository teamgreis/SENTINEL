using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Core.Users;

/// <summary>
/// Speichert die Backup-Codes (nur Hashes) und ermöglicht die Wiederherstellung
/// eines Kontos, wenn das Passwort vergessen wurde.
/// </summary>
public sealed class BackupKeyStore
{
    private readonly string _filePath;
    private List<BackupKeyEntry> _keys = new();

    public BackupKeyStore(string filePath)
    {
        _filePath = filePath;
        Load();
    }

    /// <summary>Anzahl gespeicherter Backup-Codes.</summary>
    public int Count => _keys.Count;

    /// <summary>
    /// Legt Backup-Codes für einen Nutzer an (überschreibt alte).
    /// Gibt die Klartext-Codes zur einmaligen Anzeige zurück.
    /// </summary>
    public List<string> CreateForUser(string userId, int count = 2)
    {
        var codes = new List<string>();
        for (int i = 0; i < count; i++)
            codes.Add(BackupKeyGenerator.GenerateCode());

        _keys.RemoveAll(k => k.UserId == userId);
        foreach (var code in codes)
        {
            var (salt, hash) = HashCode(code);
            _keys.Add(new BackupKeyEntry
            {
                UserId = userId,
                SaltBase64 = Convert.ToBase64String(salt),
                HashBase64 = Convert.ToBase64String(hash),
                Used = false
            });
        }

        Save();
        return codes;
    }

    /// <summary>Prüft einen Code und markiert ihn als verbraucht.</summary>
    public bool TryConsume(string userId, string code)
    {
        foreach (var entry in _keys.Where(k => k.UserId == userId && !k.Used))
        {
            if (Verify(code, entry))
            {
                entry.Used = true;
                Save();
                return true;
            }
        }
        return false;
    }

    /// <summary>Prüft, ohne zu verbrauchen.</summary>
    public bool VerifyForUser(string userId, string code)
    {
        return _keys.Where(k => k.UserId == userId && !k.Used)
            .Any(k => Verify(code, k));
    }

    /// <summary>Wie viele ungenutzte Codes hat der Nutzer noch?</summary>
    public int RemainingForUser(string userId) =>
        _keys.Count(k => k.UserId == userId && !k.Used);

    private static (byte[] Salt, byte[] Hash) HashCode(string code)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            BackupKeyGenerator.Normalize(code),
            salt,
            210_000,
            HashAlgorithmName.SHA512,
            32);
        return (salt, hash);
    }

    private static bool Verify(string code, BackupKeyEntry entry)
    {
        try
        {
            var salt = Convert.FromBase64String(entry.SaltBase64);
            var expected = Convert.FromBase64String(entry.HashBase64);
            var actual = Rfc2898DeriveBytes.Pbkdf2(
                BackupKeyGenerator.Normalize(code),
                salt,
                210_000,
                HashAlgorithmName.SHA512,
                32);
            return CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        catch
        {
            return false;
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_filePath)) return;
            var dto = JsonSerializer.Deserialize<StoreDto>(File.ReadAllText(_filePath), ReadOptions);
            _keys = dto?.Keys ?? new List<BackupKeyEntry>();
        }
        catch
        {
            _keys = new List<BackupKeyEntry>();
        }
    }

    private void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(_filePath));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var dto = new StoreDto { Keys = _keys };
            File.WriteAllText(_filePath, JsonSerializer.Serialize(dto, WriteOptions));
        }
        catch
        {
            // Nicht crashen
        }
    }

    private static readonly JsonSerializerOptions ReadOptions = new() { PropertyNameCaseInsensitive = true };
    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };

    public sealed class BackupKeyEntry
    {
        [JsonPropertyName("userId")]
        public string UserId { get; set; } = "";

        [JsonPropertyName("salt")]
        public string SaltBase64 { get; set; } = "";

        [JsonPropertyName("hash")]
        public string HashBase64 { get; set; } = "";

        [JsonPropertyName("used")]
        public bool Used { get; set; }
    }

    private sealed class StoreDto
    {
        [JsonPropertyName("keys")]
        public List<BackupKeyEntry> Keys { get; set; } = new();
    }
}
