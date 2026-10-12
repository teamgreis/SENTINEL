using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Core.Users;

/// <summary>Ergebnis eines Anmeldeversuchs.</summary>
public enum AuthResult
{
    Success,
    WrongPassword,
    Locked,
    NoUser,
    UserLocked
}

/// <summary>
/// Nutzerverwaltung mit Rollen, Sperrlogik und Multi-User.
/// Speichert Nutzer als JSON – Passwörter nur als PBKDF2-Hash.
/// </summary>
public sealed class UserManager
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    private readonly string _filePath;
    private readonly List<UserAccount> _users = new();

    public UserManager(string filePath)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        Load();
    }

    public IReadOnlyList<UserAccount> Users => _users;

    public bool HasUsers => _users.Count > 0;

    public UserAccount? CurrentUser { get; private set; }

    public bool IsAdmin => CurrentUser?.IsAdmin == true;

    /// <summary>Gibt es mindestens einen Admin? (Pflicht für den Betrieb.)</summary>
    public bool HasAdmin => _users.Any(u => u.IsAdmin);

    // ---------- Nutzer anlegen ----------

    /// <summary>Legt den ersten Nutzer an (Onboarding) – immer als Admin.</summary>
    public UserAccount CreateFirstUser(string displayName, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        if (HasUsers)
            throw new InvalidOperationException("Es existiert bereits ein Nutzer.");

        var user = CreateUser(displayName, password, UserRole.Admin);
        return user;
    }

    /// <summary>Legt einen weiteren Nutzer an (nur Admins sollten das aufrufen).</summary>
    public UserAccount AddUser(string displayName, string password, UserRole role = UserRole.User)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        if (_users.Any(u => u.DisplayName.Equals(displayName, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException($"Der Name '{displayName}' ist bereits vergeben.");

        return CreateUser(displayName, password, role);
    }

    private UserAccount CreateUser(string displayName, string password, UserRole role)
    {
        var user = new UserAccount
        {
            DisplayName = displayName,
            Password = PasswordHasher.CreateHash(password),
            Role = role
        };

        _users.Add(user);
        Save();
        return user;
    }

    /// <summary>Entfernt einen Nutzer. Verhindert, dass der letzte Admin entfernt wird.</summary>
    public bool RemoveUser(string userId, string adminPassword)
    {
        var admin = _users.FirstOrDefault(u => u.Id == userId && u.IsAdmin)
                    ?? _users.FirstOrDefault(u => u.IsAdmin);
        if (admin is null) return false;
        if (!PasswordHasher.Verify(adminPassword, admin.Password)) return false;

        var target = _users.FirstOrDefault(u => u.Id == userId);
        if (target is null) return false;

        // Letzten Admin nicht entfernen
        if (target.IsAdmin && _users.Count(u => u.IsAdmin) <= 1)
            throw new InvalidOperationException("Der letzte Administrator kann nicht entfernt werden.");

        _users.Remove(target);
        if (CurrentUser?.Id == userId) CurrentUser = null;
        Save();
        return true;
    }

    /// <summary>Ändert die Rolle eines Nutzers (Admin-Pflicht, letzten Admin schützen).</summary>
    public bool ChangeRole(string userId, UserRole newRole)
    {
        var target = _users.FirstOrDefault(u => u.Id == userId);
        if (target is null || target.Role == newRole) return false;

        // Letzten Admin nicht degradieren
        if (target.IsAdmin && newRole == UserRole.User && _users.Count(u => u.IsAdmin) <= 1)
            throw new InvalidOperationException("Der letzte Administrator kann nicht herabgestuft werden.");

        var replacement = new UserAccount
        {
            Id = target.Id,
            DisplayName = target.DisplayName,
            Password = target.Password,
            Role = newRole,
            CreatedAt = target.CreatedAt,
            LastLoginAt = target.LastLoginAt,
            FailedAttempts = target.FailedAttempts,
            LockedUntil = target.LockedUntil
        };

        int idx = _users.IndexOf(target);
        _users[idx] = replacement;
        if (CurrentUser?.Id == userId) CurrentUser = replacement;
        Save();
        return true;
    }

    // ---------- Anmeldung ----------

    /// <summary>Meldet einen Nutzer per Name + Passwort an.</summary>
    public AuthResult Login(string displayName, string password)
    {
        var now = DateTimeOffset.UtcNow;
        var user = _users.FirstOrDefault(u =>
            u.DisplayName.Equals(displayName, StringComparison.OrdinalIgnoreCase));

        if (user is null) return AuthResult.NoUser;

        if (user.IsLocked(now))
            return AuthResult.UserLocked;

        if (PasswordHasher.Verify(password, user.Password))
        {
            user.FailedAttempts = 0;
            user.LockedUntil = null;
            user.LastLoginAt = now;
            CurrentUser = user;
            Save();
            return AuthResult.Success;
        }

        user.FailedAttempts++;
        if (user.FailedAttempts >= MaxFailedAttempts)
            user.LockedUntil = now.Add(LockoutDuration);

        Save();
        return AuthResult.WrongPassword;
    }

    /// <summary>Meldet ohne Name an (Single-User-Abwärtskompatibilität).</summary>
    public AuthResult Login(string password)
    {
        var single = _users.Count == 1 ? _users[0] : null;
        if (single is null) return _users.Count == 0 ? AuthResult.NoUser : AuthResult.WrongPassword;
        return Login(single.DisplayName, password);
    }

    /// <summary>
    /// Setzt den aktuellen Nutzer ohne Passwort-Prüfung.
    /// Wird genutzt, wenn die Anmeldung bereits in einem anderen
    /// Fenster (z. B. der Sperre) erfolgreich war.
    /// </summary>
    public bool SetCurrentUser(string displayName)
    {
        var user = _users.FirstOrDefault(u =>
            u.DisplayName.Equals(displayName, StringComparison.OrdinalIgnoreCase));
        if (user is null) return false;
        CurrentUser = user;
        return true;
    }

    public void Logout() => CurrentUser = null;

    // ---------- Passwort ----------

    /// <summary>Ändert das Passwort eines Nutzers (altes muss bestätigt werden).</summary>
    public bool ChangePassword(string userId, string currentPassword, string newPassword)
    {
        var user = _users.FirstOrDefault(u => u.Id == userId);
        if (user is null) return false;
        if (!PasswordHasher.Verify(currentPassword, user.Password)) return false;

        var replacement = new UserAccount
        {
            Id = user.Id,
            DisplayName = user.DisplayName,
            Password = PasswordHasher.CreateHash(newPassword),
            Role = user.Role,
            CreatedAt = user.CreatedAt,
            LastLoginAt = user.LastLoginAt,
            FailedAttempts = 0,
            LockedUntil = null
        };

        int idx = _users.IndexOf(user);
        _users[idx] = replacement;
        if (CurrentUser?.Id == userId) CurrentUser = replacement;
        Save();
        return true;
    }

    /// <summary>Ändert das Passwort des aktuellen Nutzers.</summary>
    public bool ChangePassword(string currentPassword, string newPassword)
    {
        if (CurrentUser is null) return false;
        return ChangePassword(CurrentUser.Id, currentPassword, newPassword);
    }

    /// <summary>Setzt ein Passwort zurück (Admin-Aktion, kennt das alte nicht).</summary>
    public bool ResetPassword(string userId, string newPassword)
    {
        var user = _users.FirstOrDefault(u => u.Id == userId);
        if (user is null) return false;

        var replacement = new UserAccount
        {
            Id = user.Id,
            DisplayName = user.DisplayName,
            Password = PasswordHasher.CreateHash(newPassword),
            Role = user.Role,
            CreatedAt = user.CreatedAt,
            LastLoginAt = user.LastLoginAt
        };

        int idx = _users.IndexOf(user);
        _users[idx] = replacement;
        Save();
        return true;
    }

    // ---------- Sperre ----------

    public TimeSpan? RemainingLockout(string userId)
    {
        var user = _users.FirstOrDefault(u => u.Id == userId);
        if (user?.LockedUntil is null) return null;
        var remaining = user.LockedUntil.Value - DateTimeOffset.UtcNow;
        return remaining > TimeSpan.Zero ? remaining : null;
    }

    public TimeSpan? RemainingLockout() =>
        CurrentUser is null ? null : RemainingLockout(CurrentUser.Id);

    // ---------- Persistenz ----------

    private void Load()
    {
        try
        {
            if (!File.Exists(_filePath)) return;
            var json = File.ReadAllText(_filePath);

            // Neues Format: { "users": [...] }
            var dto = JsonSerializer.Deserialize<UserStoreDto>(json, Options);
            if (dto?.Users is { Count: > 0 })
            {
                foreach (var u in dto.Users)
                {
                    var user = UserAccount.FromJson(u);
                    if (user is not null) _users.Add(user);
                }
                return;
            }

            // Altes Format (Single-User): { "user": "..." } – migrieren
            var legacy = JsonSerializer.Deserialize<LegacyStoreDto>(json, Options);
            if (legacy?.User is not null)
            {
                var user = UserAccount.FromJson(legacy.User);
                if (user is not null)
                {
                    // Legacy-Nutzer wird Admin (er hat die App eingerichtet)
                    var migrated = new UserAccount
                    {
                        Id = user.Id,
                        DisplayName = user.DisplayName,
                        Password = user.Password,
                        Role = UserRole.Admin,
                        CreatedAt = user.CreatedAt,
                        LastLoginAt = user.LastLoginAt,
                        FailedAttempts = user.FailedAttempts,
                        LockedUntil = user.LockedUntil
                    };
                    _users.Add(migrated);
                    Save(); // in neuem Format zurückschreiben
                }
            }
        }
        catch
        {
            // Defekte Datei: Nutzer muss neu angelegt werden – aber nichts crashen
        }
    }

    private void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(_filePath));
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var dto = new UserStoreDto
            {
                Users = _users.Select(u => u.ToJson()).ToList()
            };
            File.WriteAllText(_filePath, JsonSerializer.Serialize(dto, Options));
        }
        catch
        {
            // Speichern darf die App nicht crashen
        }
    }

    private sealed class UserStoreDto
    {
        [JsonPropertyName("users")]
        public List<string> Users { get; set; } = new();
    }

    private sealed class LegacyStoreDto
    {
        [JsonPropertyName("user")]
        public string? User { get; set; }
    }
}
