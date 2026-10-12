namespace Sentinel.Core.Users;

/// <summary>
/// Erzeugt und prüft Backup-Wiederherstellungscodes.
/// Zwei Codes werden beim Einrichten angezeigt – der Nutzer soll sie ausdrucken/notieren.
/// Gespeichert wird nur der PBKDF2-Hash, nie der Code selbst.
/// </summary>
public static class BackupKeyGenerator
{
    /// <summary>Zeichen ohne Verwechslungsgefahr (kein 0/O, 1/I/l).</summary>
    private const string Alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

    /// <summary>Erzeugt einen Code im Format XXXX-XXXX-XXXX-XXXX.</summary>
    public static string GenerateCode()
    {
        var bytes = global::System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        var sb = new global::System.Text.StringBuilder(19);
        for (int i = 0; i < 16; i++)
        {
            if (i > 0 && i % 4 == 0) sb.Append('-');
            sb.Append(Alphabet[bytes[i] % Alphabet.Length]);
        }
        return sb.ToString();
    }

    /// <summary>Erzeugt zwei Codes (wie vom Nutzer gewünscht).</summary>
    public static (string Key1, string Key2) GeneratePair() => (GenerateCode(), GenerateCode());

    /// <summary>Normalisiert einen eingegebenen Code (Großbuchstaben, einheitliche Striche).</summary>
    public static string Normalize(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;

        var cleaned = new string(input.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
        if (cleaned.Length == 16)
        {
            // Ohne Striche eingegeben → passend formatieren
            var parts = new List<string>();
            for (int i = 0; i < cleaned.Length; i += 4)
                parts.Add(cleaned.Substring(i, Math.Min(4, cleaned.Length - i)));
            return string.Join("-", parts);
        }
        return cleaned;
    }

    /// <summary>Vergleicht zwei Codes zeitkonstant (kein Timing-Leck).</summary>
    public static bool Matches(string expected, string actual)
    {
        string a = Normalize(expected);
        string b = Normalize(actual);
        if (a.Length == 0 || a.Length != b.Length) return false;

        // Zeitkonstanter Vergleich
        uint diff = 0;
        for (int i = 0; i < a.Length; i++)
            diff |= (uint)(a[i] ^ b[i]);
        return diff == 0;
    }
}
