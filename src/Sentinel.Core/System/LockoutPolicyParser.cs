namespace Sentinel.Core.System;

/// <summary>
/// Parser für die Kontosperr-Richtlinie (net accounts).
/// Sprachrobust: sucht die Zahl hinter dem Doppelpunkt.
/// </summary>
public static class LockoutPolicyParser
{
    /// <summary>
    /// Liest die Sperrschwelle. Gibt -1 zurück, wenn keine Zeile mit
    /// „Schwelle\"/„threshold\" gefunden wurde.
    /// </summary>
    public static int ParseThreshold(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return -1;

        foreach (var line in text.Split('\n'))
        {
            var l = line.Trim();
            if (!l.Contains("Schwelle", StringComparison.OrdinalIgnoreCase) &&
                !l.Contains("threshold", StringComparison.OrdinalIgnoreCase))
                continue;

            int idx = l.IndexOf(':');
            if (idx < 0) continue;

            string rest = l[(idx + 1)..].Trim();
            var digits = new string(rest.TakeWhile(char.IsDigit).ToArray());
            if (int.TryParse(digits, out var value))
                return value;
        }
        return -1;
    }
}
