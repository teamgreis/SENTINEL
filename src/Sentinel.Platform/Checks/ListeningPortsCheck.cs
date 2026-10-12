using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft lauschende riskante Ports (RDP, WinRM, SMB etc.). Read-only.</summary>
public sealed class ListeningPortsCheck : ICheck
{
    public string Id => "network.listeningports";
    public string Title => "Offene Server-Ports";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob riskante Server-Ports auf eingehende Verbindungen warten.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 23,21,135,139,445,3389,5900,5985,5986 } | ForEach-Object { \"$($_.LocalPort)|$($_.State)|$((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName)\" }",
                ct).ConfigureAwait(false);

            var risky = ListeningPortsAnalyzer.AnalyzeRisky(output);

            if (risky.Count == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Keine riskanten Server-Ports lauschen.",
                    Explanation = "RDP, SMB, WinRM und Co. nehmen keine eingehenden Verbindungen an – im Netzwerk kann niemand diese Dienste erreichen.",
                    Source = "Get-NetTCPConnection"
                };
            }

            var names = risky.Select(p => $"{p.Port} ({ListeningPortsAnalyzer.RiskyPorts.GetValueOrDefault(p.Port, "?")})").ToList();

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Warning,
                Detail = $"Lauschende riskante Ports: {string.Join(", ", names)}.",
                Explanation = "Diese Ports akzeptieren eingehende Verbindungen. Im eigenen Netzwerk kann jeder andere Rechner sie erreichen – bei RDP oder WinRM ist das ein direkter Angriffspfad.",
                RecommendedActions = new[]
                {
                    "Nicht benötigte Dienste deaktivieren (services.msc).",
                    "Firewall-Regeln prüfen: eingehende Verbindungen auf diese Ports blockieren.",
                    "Bei RDP: nur im privaten Netzwerk aktiv lassen, nie im öffentlichen."
                },
                Source = "Get-NetTCPConnection"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "network.listeningports", Title = "Offene Server-Ports", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe mit 'netstat -an' in PowerShell, welche Ports lauschen.",
        Source = "Get-NetTCPConnection"
    };
}
