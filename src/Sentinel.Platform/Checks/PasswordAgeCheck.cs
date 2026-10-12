using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft das Passwort-Alter des aktuellen Benutzers.
/// Sehr alte Passworter sind ein Risiko (geleakt, geteilt, notiert).
/// </summary>
public sealed class PasswordAgeCheck : ICheck
{
    public string Id => "accounts.passwordage";
    public string Title => "Passwort-Alter";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft, wie alt das Passwort des aktuellen Kontos ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            string user = Environment.UserName;
            var (output, error) = await PowerShell.RunAsync(
                $"(net user \"{user}\" | Select-String -Pattern 'Passwort letzte|Password last' -Context 0,1) -join ' '",
                ct).ConfigureAwait(false);

            string combined = output + " " + error;

            // Datum finden (Format variiert: 12.10.2026 oder 10/12/2026)
            var match = System.Text.RegularExpressions.Regex.Match(combined,
                @"(\d{1,2})[./](\d{1,2})[./](\d{4})");

            if (!match.Success)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Unknown,
                    Detail = "Passwort-Änderungsdatum nicht lesbar.",
                    Explanation = "Prüfe als Administrator mit 'net user <name>', wann das Passwort zuletzt geändert wurde.",
                    Source = $"net user {user}"
                };
            }

            if (DateTime.TryParse($"{match.Groups[3].Value}-{match.Groups[2].Value.PadLeft(2, '0')}-{match.Groups[1].Value.PadLeft(2, '0')}", out var lastChange))
            {
                int days = (int)(DateTime.Now - lastChange).TotalDays;

                if (days > 365)
                {
                    return new CheckResult
                    {
                        Id = Id, Title = Title, Weight = Weight,
                        Status = CheckStatus.Warning,
                        Detail = $"Das Passwort ist {days} Tage alt (letzte Änderung {lastChange:dd.MM.yyyy}).",
                        Explanation = "Sehr alte Passwörter sind oft in Datenleaks enthalten oder in Umgebungen notiert. Ein jährlicher Wechsel ist sinnvoll.",
                        RecommendedActions = new[]
                        {
                            "Einstellungen → Konten → Anmeldeoptionen → Passwort ändern.",
                            "Nutze einen Passwort-Manager für starke, einzigartige Passwörter."
                        },
                        Source = $"net user {user}"
                    };
                }

                if (days < 0)
                {
                    return new CheckResult
                    {
                        Id = Id, Title = Title, Weight = Weight,
                        Status = CheckStatus.Info,
                        Detail = "Das Passwort wurde noch nie geändert („Passwort läuft nie ab\" aktiv).",
                        Explanation = "Ein nie geändertes Passwort ist praktisch, aber bei einem Leak bleibt es dauerhaft gültig.",
                        Source = $"net user {user}"
                    };
                }

                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = $"Das Passwort ist {days} Tage alt (letzte Änderung {lastChange:dd.MM.yyyy}).",
                    Explanation = "Das Passwort ist relativ frisch geändert worden.",
                    Source = $"net user {user}"
                };
            }

            return Unknown();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown() => new()
    {
        Id = "accounts.passwordage", Title = "Passwort-Alter", Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown,
        Detail = "Prüfung nicht möglich.",
        Explanation = "Nur für lokale Konten ermittelbar; bei Microsoft-Konten zeigt Windows das Datum nicht an.",
        Source = "net user"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
