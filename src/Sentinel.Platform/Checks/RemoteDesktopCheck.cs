using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft den Remotedesktop-Status – offenes RDP ist ein großes Risiko.</summary>
public sealed class RemoteDesktopCheck : ICheck
{
    public string Id => "network.rdp";
    public string Title => "Remotedesktop";
    public CheckWeight Weight => CheckWeight.High;
    public string Description => "Prüft, ob Remotedesktop aktiviert ist (fDenyTSConnections).";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 } && output.Length == 0)
                return Unknown("RDP-Einstellung konnte nicht gelesen werden.");

            if (string.IsNullOrWhiteSpace(output))
                return Unknown("Keine RDP-Richtlinie gefunden.");

            // 1 = Verbindungen VERBIETEN (sicher), 0 = erlaubt
            bool denied = output.Trim() == "1";

            if (denied)
                return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = "Remotedesktop ist deaktiviert.",
                Explanation = "Ohne RDP gibt es keine offene Fernzugriffstür. Das ist empfohlen, solange du es nicht bewusst nutzt.",
                Source = "Registry: Terminal Server (fDenyTSConnections)"
            };

            // RDP an – prüfe noch den Netzwerk-Level-Auth-Status
            var (nlaOutput, _) = await PowerShell.RunAsync(
                "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication",
                ct).ConfigureAwait(false);
            bool nla = nlaOutput.Trim() == "1";

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = nla ? CheckStatus.Warning : CheckStatus.Fail,
                Detail = nla
                    ? "Remotedesktop ist aktiviert (mit Netzwerkauthentifizierung)."
                    : "Remotedesktop ist aktiviert OHNE Netzwerkauthentifizierung.",
                Explanation = nla
                    ? "RDP ist offen. Mit NLA ist das deutlich sicherer, aber ein offener RDP-Port bleibt ein Angriffsziel – besonders ohne starkes Passwort."
                    : "RDP ohne NLA ist hochriskant: Angreifer können Anmeldeversuche ohne Vorauthentifizierung starten (Brute-Force, „BlueKeep\"-ähnliche Szenarien).",
                RecommendedActions = new[]
                {
                    "Wenn du RDP nicht brauchst: Einstellungen → System → Remotedesktop → ausschalten.",
                    "Wenn du es brauchst: starkes Passwort, NLA aktivieren, und RDP nur über VPN erreichbar machen.",
                    "Firewall prüfen: Port 3389 sollte nicht aus dem Internet offen sein."
                },
                Source = "Registry: Terminal Server"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("RDP-Status konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "network.rdp",
        Title = "Remotedesktop",
        Weight = CheckWeight.High,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Prüfe manuell: Einstellungen → System → Remotedesktop. Empfohlen: aus.",
        Source = "Registry"
    };
}
