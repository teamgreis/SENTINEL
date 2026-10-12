using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft die Kontosperr-Richtlinie (Lockout). Read-only über net accounts.</summary>
public sealed class LockoutPolicyCheck : ICheck
{
    public string Id => "accounts.lockoutpolicy";
    public string Title => "Kontosperrung";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob nach Fehlversuchen eine Kontosperre greift.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync("net accounts", ct).ConfigureAwait(false);
            string combined = output + "\n" + error;

            // "Sperrschwelle: 5" / "Lockout threshold: 5"
            int threshold = ParseThreshold(combined);

            if (threshold == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Fail,
                    Detail = "Es gibt keine Kontosperre (Sperrschwelle: 0 = unbegrenzte Versuche).",
                    Explanation = "Ohne Kontosperre kann ein Angreifer Passwörter unbegrenzt oft ausprobieren – lokal oder über Remote-Desktop.",
                    RecommendedActions = new[]
                    {
                        "Als Administrator: secpol.msc → Kontorichtlinien → Kontosperrungsrichtlinie.",
                        "Sperrschwelle auf 5 Fehlversuche, Sperrdauer 15 Minuten setzen."
                    },
                    Source = "net accounts"
                };
            }

            if (threshold > 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = $"Kontosperre nach {threshold} Fehlversuchen aktiv.",
                    Explanation = "Brute-Force-Angriffe werden nach wenigen Versuchen gestoppt.",
                    Source = "net accounts"
                };
            }

            return Unknown();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    /// <summary>Liest die Sperrschwelle. Sprachrobust: sucht die Zahl hinter dem Doppelpunkt.</summary>
    internal static int ParseThreshold(string text) => LockoutPolicyParser.ParseThreshold(text);

    private static CheckResult Unknown() => new()
    {
        Id = "accounts.lockoutpolicy", Title = "Kontosperrung", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = "Kontosperr-Richtlinie konnte nicht gelesen werden.",
        Explanation = "Prüfe als Administrator in secpol.msc → Kontorichtlinien → Kontosperrungsrichtlinie.",
        Source = "net accounts"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
