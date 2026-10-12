using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft, ob RDP-Verbindungen NLA (Network Level Authentication) erfordern. Read-only.</summary>
public sealed class RdpNlaCheck : ICheck
{
    public string Id => "network.rdpnla";
    public string Title => "RDP-Anmeldesicherheit";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob Remotedesktop Netzwerkauthentifizierung verlangt.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$k = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp'; " +
                "\"$((Get-ItemProperty $k -ErrorAction SilentlyContinue).UserAuthentication)|$((Get-ItemProperty $k -ErrorAction SilentlyContinue).SecurityLayer)\"",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();
            var parts = combined.Split('|');

            string userAuth = parts.Length > 0 ? parts[0].Trim() : "";
            string secLayer = parts.Length > 1 ? parts[1].Trim() : "";

            if (userAuth == "1" || combined.Contains("kein") || combined.Length == 0)
            {
                // 1 = NLA erforderlich (der sichere Wert)
                if (userAuth == "1")
                {
                    return new CheckResult
                    {
                        Id = Id, Title = Title, Weight = Weight,
                        Status = CheckStatus.Pass,
                        Detail = "RDP verlangt Netzwerkauthentifizierung (NLA).",
                        Explanation = "Der Anmeldedialog erscheint, bevor die Remotesitzung aufgebaut wird – das blockiert viele automatisierte Angriffe auf RDP.",
                        Source = "Registry (RDP-Tcp)"
                    };
                }

                return Unknown();
            }

            if (userAuth == "0")
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "RDP verlangt KEINE Netzwerkauthentifizierung.",
                    Explanation = "Ohne NLA baut Windows die Sitzung auf, bevor sich jemand anmeldet. Angreifer können den Anmeldebildschirm erreichen und Passwörter ausprobieren, ohne eine gültige Sitzung zu brauchen.",
                    RecommendedActions = new[]
                    {
                        "System → Erweiterte Systemeinstellungen → Remote → Netzwerkauthentifizierung verlangen.",
                        "Oder: Remotedesktop ganz deaktivieren, wenn nicht gebraucht."
                    },
                    Source = "Registry (RDP-Tcp)"
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
        Id = "network.rdpnla", Title = "RDP-Anmeldesicherheit", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = "RDP-Einstellungen nicht abfragbar (evtl. RDP deaktiviert).",
        Explanation = "Wenn Remotedesktop deaktiviert ist, ist dieses Check nicht relevant.",
        Source = "Registry (RDP-Tcp)"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
