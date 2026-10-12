using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft die Angriffsflächenreduzierung (ASR) von Defender.
/// ASR-Regeln blockieren gängige Malware-Techniken (Office-Makros, WMI, etc.).
/// </summary>
public sealed class AsrRulesCheck : ICheck
{
    public string Id => "system.asrrules";
    public string Title => "Angriffsflächenreduzierung (ASR)";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob Defender-ASR-Regeln konfiguriert sind.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$r = (Get-MpPreference).AttackSurfaceReductionRules_Ids; if ($r) { $r.Count } else { 0 }",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();
            int count = int.TryParse(combined.Split('\n')[0].Trim(), out var c) ? c : -1;

            if (count == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "Keine ASR-Regeln aktiv.",
                    Explanation = "Angriffsflächenreduzierung blockiert gängige Malware-Techniken wie Office-Makros, WMI-Aufrufe oder verschleierte Skripte – eine der wirksamsten Defender-Funktionen.",
                    RecommendedActions = new[]
                    {
                        "Windows-Sicherheit → Virus- und Bedrohungsschutz → Einstellungen verwalten → Angriffsflächenreduzierung.",
                        "Microsoft empfiehlt: Alle Regeln im Überwachungsmodus starten, dann aktivieren."
                    },
                    Source = "Get-MpPreference (ASR)"
                };
            }

            if (count > 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = $"{count} ASR-Regel(n) konfiguriert.",
                    Explanation = "Die Angriffsflächenreduzierung blockiert gängige Angriffstechniken. Prüfe regelmäßig die Blockier-Ereignisse in der Windows-Sicherheit.",
                    Source = "Get-MpPreference (ASR)"
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
        Id = "system.asrrules", Title = "Angriffsflächenreduzierung (ASR)", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = "ASR-Status nicht abfragbar.",
        Explanation = "Prüfe in der Windows-Sicherheit unter Virus- und Bedrohungsschutz → Einstellungen verwalten.",
        Source = "Get-MpPreference (ASR)"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
