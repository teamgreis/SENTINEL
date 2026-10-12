using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft, ob das Gastkonto aktiv ist. Gastkonten sind ein beliebtes Einfallstor.
/// Read-only Registry-Abfrage.
/// </summary>
public sealed class GuestAccountCheck : ICheck
{
    public string Id => "accounts.guest";
    public string Title => "Gastkonto";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob das eingebaute Gastkonto aktiviert ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            // Flags: 0x0001 = aktiv, 0x0002 = deaktiviert (je nach Quelle unterschiedlich,
            // wir prüfen zuerst den sicheren Wert und melden Unklarheit bei Nicht-Fund)
            var (output, error) = await PowerShell.RunAsync(
                "(net user Gast | Select-String -Pattern 'Konto aktiv' -Context 0,1) -join ' '",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).ToLowerInvariant();

            if (combined.Contains("nein") || combined.Contains("no"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Das Gastkonto ist deaktiviert.",
                    Explanation = "Gastkonten erlauben Anmeldungen ohne Passwort. Deaktiviert ist der empfohlene Zustand.",
                    Source = "net user Gast"
                };
            }

            if (combined.Contains("ja") || combined.Contains("yes"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Fail,
                    Detail = "Das Gastkonto ist aktiv.",
                    Explanation = "Jeder, der physischen Zugriff auf den PC hat, kann sich ohne Passwort als Gast anmelden und das System erkunden.",
                    RecommendedActions = new[]
                    {
                        "Einstellungen → Konten → Familie und andere Benutzer.",
                        "Gastkonto deaktivieren (Systemsteuerung → Benutzerkonten → Andere Konten verwalten → Gast aktivieren/deaktivieren)."
                    },
                    Source = "net user Gast"
                };
            }

            return Unknown("Der Status des Gastkontos konnte nicht ermittelt werden (Systemsprache nicht Deutsch/Englisch?).");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("Gastkonto-Status konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "accounts.guest",
        Title = "Gastkonto",
        Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Prüfe manuell unter Systemsteuerung → Benutzerkonten, ob das Gastkonto aktiv ist. Empfohlen: deaktiviert.",
        Source = "net user Gast"
    };
}
