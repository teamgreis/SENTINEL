using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft die Berechtigungen der administrativen Freigaben (C$, ADMIN$).
/// Read-only über net share.
/// </summary>
public sealed class AdminShareCheck : ICheck
{
    public string Id => "network.adminshares";
    public string Title => "Administrative Freigaben";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft die administrativen Freigaben (C$, ADMIN$).";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync("net share", ct).ConfigureAwait(false);
            string combined = output + "\n" + error;

            var shares = combined.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Trim())
                .Where(l => l.EndsWith("$") || l.Contains("C$") || l.Contains("ADMIN$"))
                .ToList();

            if (shares.Count == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Keine administrativen Freigaben aktiv.",
                    Explanation = "C$ und ADMIN$ sind die Standardfreigaben von Windows. Deaktiviert ist restriktiver – Remote-Zugriff auf das Dateisystem ist dann nicht möglich.",
                    Source = "net share"
                };
            }

            // Zählen: Nur Info, da Standardfreigaben in Firmennetzen gebraucht werden
            int adminShares = shares.Count;

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Info,
                Detail = $"{adminShares} administrative Freigabe(n) aktiv: {string.Join(", ", shares.Take(5))}.",
                Explanation = "Die administrativen Freigaben erlauben Administratoren den Remote-Zugriff auf Laufwerke. In einem Heimnetzwerk sind sie meist nicht nötig und können unter Computerverwaltung → Freigegebene Ordner → Freigaben deaktiviert werden.",
                Source = "net share",
                Limitations = "SENTINEL ändert nichts – die Deaktivierung ist ein manueller Schritt."
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "network.adminshares", Title = "Administrative Freigaben", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe mit 'net share' in PowerShell, welche Freigaben existieren.",
        Source = "net share"
    };
}
