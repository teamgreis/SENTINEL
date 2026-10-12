using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft, ob die automatische Anmeldung aktiv ist.
/// Aktiv = kritisch, weil dann jeder physischen Zugriff hat.
/// Read-only Registry-Abfrage.
/// </summary>
public sealed class AutoLoginCheck : ICheck
{
    public string Id => "accounts.autologin";
    public string Title => "Automatische Anmeldung";
    public CheckWeight Weight => CheckWeight.High;
    public string Description => "Prüft, ob sich Windows ohne Passwort automatisch anmeldet.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -ErrorAction SilentlyContinue).AutoAdminLogon",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 } && output.Length == 0)
                return Unknown("Anmelde-Einstellung konnte nicht gelesen werden.");

            bool autoLogin = output.Trim() == "1";

            if (autoLogin)
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Fail,
                    Detail = "Die automatische Anmeldung ist aktiviert.",
                    Explanation = "Jeder, der den PC einschaltet, kommt ohne Passwort direkt auf den Desktop. Bei Diebstahl oder unbefugtem Zugriff sind alle Daten sofort offen.",
                    RecommendedActions = new[]
                    {
                        "Windows-Taste + R → „netplwiz“.",
                        "Haken bei „Benutzer müssen Benutzernamen und Kennwort eingeben“ setzen.",
                        "Falls dort kein Haken nötig ist: Systemsteuerung → Benutzerkonten → Anmeldeoptionen prüfen."
                    },
                    Source = "Registry: Winlogon (AutoAdminLogon)"
                };

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = "Keine automatische Anmeldung erkannt.",
                Explanation = "Windows fragt beim Start nach dem Passwort. Das schützt vor unbefugtem Zugriff, wenn das Gerät unbeaufsichtigt ist.",
                Source = "Registry: Winlogon (AutoAdminLogon)"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("Anmeldestatus konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "accounts.autologin",
        Title = "Automatische Anmeldung",
        Weight = CheckWeight.High,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Prüfe manuell: Windows-Taste + R → „netplwiz“ → ist der Haken bei „Benutzer müssen Benutzernamen und Kennwort eingeben“ gesetzt?",
        Source = "Registry"
    };
}
