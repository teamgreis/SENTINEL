using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft, ob unverschlüsselte Remoteverbindungen (Telnet, FTP) möglich sind.
/// Read-only über die Firewall-Regeln.
/// </summary>
public sealed class TelnetFtpCheck : ICheck
{
    public string Id => "network.telnetftp";
    public string Title => "Unsichere Protokolle";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob Telnet/FTP-Server aktiv sind.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$t = Get-Service Telnet -ErrorAction SilentlyContinue; " +
                "$f = Get-Service ftpsvc -ErrorAction SilentlyContinue; " +
                "$tState = if ($t) { $t.Status } else { 'nicht installiert' }; " +
                "$fState = if ($f) { $f.Status } else { 'nicht installiert' }; " +
                "\"$tState|$fState\"",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();
            var parts = combined.Split('|');

            string telnetState = parts.Length > 0 ? parts[0] : "";
            string ftpState = parts.Length > 1 ? parts[1] : "";

            bool telnetRunning = telnetState.Equals("Running", StringComparison.OrdinalIgnoreCase);
            bool ftpRunning = ftpState.Equals("Running", StringComparison.OrdinalIgnoreCase);

            if (telnetRunning || ftpRunning)
            {
                var running = new List<string>();
                if (telnetRunning) running.Add("Telnet");
                if (ftpRunning) running.Add("FTP");

                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Fail,
                    Detail = $"Unsichere Serverdienste aktiv: {string.Join(", ", running)}.",
                    Explanation = "Telnet und FTP übertragen Passwörter im Klartext. Jeder im Netz kann sie mitlesen. SSH und SFTP sind die sicheren Alternativen.",
                    RecommendedActions = new[]
                    {
                        "Dienste deaktivieren: services.msc → Telnet / FTP-Publishingdienst.",
                        "Stattdessen SSH/SFTP nutzen."
                    },
                    Source = "Get-Service"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = "Weder Telnet noch FTP-Server sind aktiv.",
                Explanation = "Klartext-Dienste sind deaktiviert – Passwörter können nicht im Netz mitgelesen werden.",
                Source = "Get-Service"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "network.telnetftp", Title = "Unsichere Protokolle", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe in services.msc, ob Telnet oder FTP-Dienste laufen.",
        Source = "Get-Service"
    };
}
