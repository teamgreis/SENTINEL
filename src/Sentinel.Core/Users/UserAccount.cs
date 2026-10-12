using System.Security.Cryptography;
using System.Text.Json;

namespace Sentinel.Core.Users;

/// <summary>Ein Nutzerkonto. Der Klartext-Passwort existiert nie gespeichert.</summary>
public sealed class UserAccount
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public required string DisplayName { get; set; }
    public required PasswordHash Password { get; init; }
    public UserRole Role { get; init; } = UserRole.User;
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastLoginAt { get; set; }

    /// <summary>Anzahl fehlgeschlagener Anmeldeversuche (Sperrlogik).</summary>
    public int FailedAttempts { get; set; }

    /// <summary>Gesperrt bis zu diesem Zeitpunkt (leer = nicht gesperrt).</summary>
    public DateTimeOffset? LockedUntil { get; set; }

    public bool IsLocked(DateTimeOffset now) => LockedUntil.HasValue && LockedUntil > now;

    public bool IsAdmin => Role == UserRole.Admin;

    // JSON-Serialisierung: Salt/Hash als Base64
    internal string SaltBase64 => Convert.ToBase64String(Password.Salt);
    internal string HashBase64 => Convert.ToBase64String(Password.Hash);
    internal int Iterations => Password.Iterations;

    public string ToJson()
    {
        var dto = new UserDto
        {
            Id = Id,
            DisplayName = DisplayName,
            Salt = SaltBase64,
            Hash = HashBase64,
            Iterations = Iterations,
            Role = Role.ToString(),
            CreatedAt = CreatedAt,
            LastLoginAt = LastLoginAt,
            FailedAttempts = FailedAttempts,
            LockedUntil = LockedUntil
        };
        return JsonSerializer.Serialize(dto);
    }

    public static UserAccount? FromJson(string json)
    {
        try
        {
            var dto = JsonSerializer.Deserialize<UserDto>(json);
            if (dto is null || string.IsNullOrEmpty(dto.Salt) || string.IsNullOrEmpty(dto.Hash))
                return null;

            return new UserAccount
            {
                Id = dto.Id ?? Guid.NewGuid().ToString("N"),
                DisplayName = dto.DisplayName ?? "Unbekannt",
                Password = new PasswordHash(
                    Convert.FromBase64String(dto.Salt!),
                    Convert.FromBase64String(dto.Hash!),
                    dto.Iterations),
                Role = Enum.TryParse<UserRole>(dto.Role, out var role) ? role : UserRole.User,
                CreatedAt = dto.CreatedAt,
                LastLoginAt = dto.LastLoginAt,
                FailedAttempts = dto.FailedAttempts,
                LockedUntil = dto.LockedUntil
            };
        }
        catch
        {
            return null;
        }
    }

    private sealed class UserDto
    {
        public string? Id { get; set; }
        public string? DisplayName { get; set; }
        public string? Salt { get; set; }
        public string? Hash { get; set; }
        public int Iterations { get; set; }
        public string? Role { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset? LastLoginAt { get; set; }
        public int FailedAttempts { get; set; }
        public DateTimeOffset? LockedUntil { get; set; }
    }
}
