using System.Security.Cryptography;

namespace Sentinel.Core.Users;

/// <summary>
/// Passwort-Hashing nach aktuellem Stand: PBKDF2-SHA512.
/// Iterationen bewusst hoch gewählt (OWASP-Empfehlung 2023: ≥ 210.000 für SHA512).
/// Der Vergleich ist zeitkonstant (Timing-Angriffe).
/// </summary>
public static class PasswordHasher
{
    public const int DefaultIterations = 210_000;
    public const int SaltBytes = 16;
    public const int HashBytes = 32;

    /// <summary>Erzeugt Salt+Hash für ein neues Passwort.</summary>
    public static PasswordHash CreateHash(string password, int iterations = DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(password);

        byte[] salt = RandomNumberGenerator.GetBytes(SaltBytes);
        byte[] hash = Derive(password, salt, iterations);

        return new PasswordHash(salt, hash, iterations);
    }

    /// <summary>Prüft ein Passwort gegen einen gespeicherten Hash.</summary>
    public static bool Verify(string password, PasswordHash stored)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(stored);

        byte[] candidate = Derive(password, stored.Salt, stored.Iterations);
        return CryptographicOperations.FixedTimeEquals(candidate, stored.Hash);
    }

    /// <summary>Bewertet die Stärke eines Passworts (0–100).</summary>
    public static PasswordStrength ScoreStrength(string password)
    {
        if (string.IsNullOrEmpty(password))
            return new PasswordStrength(0, "Kein Passwort", Array.Empty<string>());

        int score = 0;
        var hints = new List<string>();

        // Länge (dominanter Faktor – ein langes Passwort ist schwer zu knacken)
        score += password.Length >= 16 ? 60
            : password.Length >= 12 ? 45
            : password.Length >= 8 ? 25
            : Math.Min(password.Length * 4, 20);

        // Zeichenvielfalt
        bool hasLower = password.Any(char.IsLower);
        bool hasUpper = password.Any(char.IsUpper);
        bool hasDigit = password.Any(char.IsDigit);
        bool hasSymbol = password.Any(c => !char.IsLetterOrDigit(c));
        int variety = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);
        score += variety * 6;

        // Länge allein reicht nicht bei reinen Wörterbuch-Kandidaten
        string lower = password.ToLowerInvariant();
        string[] common = { "passwort", "password", "123456", "admin", "qwertz", "hallo", "sommer", "winter", "schatz", "liebe" };
        if (common.Any(c => lower.Contains(c)))
        {
            score -= 30;
            hints.Add("Enthält ein häufiges Wort (z. B. „passwort\") – leicht zu erraten.");
        }

        // Wiederholungen
        if (password.Length >= 3 && password.Distinct().Count() <= 2)
        {
            score -= 15;
            hints.Add("Besteht fast nur aus sich wiederholenden Zeichen.");
        }

        // Sequenzen
        if (ContainsSequence(lower))
        {
            score -= 10;
            hints.Add("Enthält eine Tastatur- oder Zahlenfolge (z. B. „abc\" oder „123\").");
        }

        // Hinweise für Verbesserungen
        if (password.Length < 12)
            hints.Add($"Mindestens 12 Zeichen verwenden (aktuell {password.Length}).");
        if (!hasSymbol)
            hints.Add("Mindestens ein Sonderzeichen ergänzen.");
        if (!hasUpper || !hasLower)
            hints.Add("Groß- und Kleinbuchstaben mischen.");
        if (!hasDigit)
            hints.Add("Mindestens eine Ziffer ergänzen.");

        score = Math.Clamp(score, 0, 100);

        string label = score switch
        {
            >= 80 => "Stark",
            >= 60 => "Ordentlich",
            >= 35 => "Schwach",
            _ => "Sehr schwach"
        };

        return new PasswordStrength(score, label, hints);
    }

    private static bool ContainsSequence(string s)
    {
        for (int i = 0; i + 2 < s.Length; i++)
        {
            if (s[i + 1] - s[i] == 1 && s[i + 2] - s[i] == 2)
                return true;
            if (s[i] - s[i + 1] == 1 && s[i + 2] - s[i + 1] == 1)
                return true;
        }
        return false;
    }

    private static byte[] Derive(string password, byte[] salt, int iterations)
    {
        // Pbkdf2 ist in .NET 8 über Rfc2898DeriveBytes.Pbkdf2 mit SHA512 verfügbar
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA512);
        return pbkdf2.GetBytes(HashBytes);
    }
}

/// <summary>Ein gespeicherter Passwort-Hash (Salt bleibt beim Nutzer, nie im Klartext).</summary>
public sealed record PasswordHash
{
    public byte[] Salt { get; }
    public byte[] Hash { get; }
    public int Iterations { get; }

    public PasswordHash(byte[] salt, byte[] hash, int iterations)
    {
        Salt = salt;
        Hash = hash;
        Iterations = iterations;
    }
}

/// <summary>Bewertung der Passwortstärke.</summary>
public sealed record PasswordStrength(int Score, string Label, IReadOnlyList<string> ImprovementHints);
