using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft, wie viele lokale Administratoren es gibt.
/// Viele Admins = viele Wege, Schadsoftware mit vollen Rechten zu installieren.
/// </summary>
public sealed class LocalAdminCountCheck : ICheck
{
    public string Id => "accounts.localadmins";
    public string Title => "Lokale Administratoren";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft die Anzahl der lokalen Administratorkonten.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(net localgroup Administratoren | Select-Object -Skip 6) -join '|'", ct).ConfigureAwait(false);

            var names = (output + "|" + error)
                .Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(n => !n.StartsWith("Der Befehl") && !n.StartsWith("The command"))
                .ToList();

            // Administrator (de) / Administrator (en) ist das eingebaute Konto
            var realAdmins = names.Where(n =>
                !n.Equals("Administrator", StringComparison.OrdinalIgnoreCase) &&
                !n.Equals("Administrator (deaktiviert)", StringComparison.OrdinalIgnoreCase) &&
                !n.Contains("erfolgreich") && !n.Contains("completed"))
                .ToList();

            if (realAdmins.Count <= 1)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = realAdmins.Count == 1
                        ? $"Ein Administratorkonto (plus eingebautes Konto): {realAdmins[0]}."
                        : "Nur das eingebaute Administratorkonto ist aktiv.",
                    Explanation = "Wenige Administratoren bedeuten weniger Konten, über die Malware volle Rechte erlangen kann.",
                    Source = "net localgroup Administratoren"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Warning,
                Detail = $"{realAdmins.Count} Administratorkonten: {string.Join(", ", realAdmins)}.",
                Explanation = "Jedes zusätzliche Adminkonto ist ein weiterer Weg, mit dem Malware volle Systemrechte bekommen kann – besonders wenn es ein Alltagskonto ist.",
                RecommendedActions = new[]
                {
                    "Alltagskonten sollten NICHT Administrator sein.",
                    "Unnötige Adminkonten entfernen: Systemsteuerung → Benutzerkonten → Anderes Konto → Kontotyp ändern."
                },
                Source = "net localgroup Administratoren"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "accounts.localadmins", Title = "Lokale Administratoren", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown, Detail = "Admin-Liste nicht lesbar: " + msg,
        Explanation = "Prüfe in der Systemsteuerung → Benutzerkonten, wer Administrator ist.",
        Source = "net localgroup Administratoren"
    };
}
