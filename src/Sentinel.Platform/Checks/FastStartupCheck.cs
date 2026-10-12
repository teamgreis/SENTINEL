using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft, ob die Fast-Startup-Option (Schnellstart) aktiv ist. Read-only.</summary>
public sealed class FastStartupCheck : ICheck
{
    public string Id => "system.faststartup";
    public string Title => "Schnellstart";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft den Windows-Schnellstart (Hybrid Shutdown).";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' -ErrorAction SilentlyContinue).HiberbootEnabled",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();

            if (combined.Contains("1") || combined.Contains("true"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Info,
                    Detail = "Schnellstart ist aktiv.",
                    Explanation = "Beim 'Herunterfahren' wird der Kernel nicht komplett beendet, sondern eingefroren. Das spart Zeit, kann aber Treiber- und Update-Probleme verursachen und verhindert echte Sicherheits-Resets.",
                    RecommendedActions = new[]
                    {
                        "Bei Update-Problemen: Energieoptionen → Netzschalter → Schnellstart deaktivieren."
                    },
                    Source = "Registry (HiberbootEnabled)"
                };
            }

            if (combined.Contains("0") || combined.Contains("false"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Schnellstart ist deaktiviert (vollständiges Herunterfahren).",
                    Explanation = "Windows fährt bei jedem Herunterfahren komplett runter – Updates und Treiber wirken sofort, keine halben Zustände.",
                    Source = "Registry (HiberbootEnabled)"
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
        Id = "system.faststartup", Title = "Schnellstart", Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown,
        Detail = "Nicht abfragbar.",
        Explanation = "Energieoptionen → Netzschalterverhalten → Schnellstart.",
        Source = "Registry (HiberbootEnabled)"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
