using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft, ob Ransomware-Schutz (kontrollierter Ordnerzugriff) aktiv ist.
/// Read-only über Get-MpPreference.
/// </summary>
public sealed class ControlledFolderAccessCheck : ICheck
{
    public string Id => "system.controlledfolderaccess";
    public string Title => "Ransomware-Schutz";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft den kontrollierten Ordnerzugriff (Ransomware-Schutz).";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(Get-MpPreference).EnableControlledFolderAccess", ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim().ToLowerInvariant();

            // 0 = deaktiviert, 1 = aktiv, 2 = Überwachung
            if (combined.Contains("1") || combined.Contains("enabled") || combined.Contains("true"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Ransomware-Schutz (kontrollierter Ordnerzugriff) ist aktiv.",
                    Explanation = "Apps, die nicht auf der Positivliste stehen, dürfen Dokumente, Bilder und Desktop nicht verändern – der wirksamste Schutz gegen Erpressungstrojaner.",
                    Source = "Get-MpPreference (EnableControlledFolderAccess)"
                };
            }

            if (combined.Contains("2") || combined.Contains("audit"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "Ransomware-Schutz läuft im Überwachungsmodus.",
                    Explanation = "Im Überwachungsmodus werden Ereignisse nur protokolliert, aber nicht blockiert. Aktiviere ihn zum Schutz.",
                    RecommendedActions = new[]
                    {
                        "Windows-Sicherheit → Virus- und Bedrohungsschutz → Einstellungen verwalten → Ransomware-Schutz.",
                        "Auf 'Aktiviert' umstellen."
                    },
                    Source = "Get-MpPreference"
                };
            }

            if (combined.Contains("0") || combined.Contains("disabled"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "Ransomware-Schutz ist deaktiviert.",
                    Explanation = "Ohne kontrollierten Ordnerzugriff kann jedes Programm deine Dokumente, Bilder und Fotos verschlüsseln – genau das macht Ransomware.",
                    RecommendedActions = new[]
                    {
                        "Windows-Sicherheit → Virus- und Bedrohungsschutz → Ransomware-Schutz verwalten.",
                        "Kontrollierten Ordnerzugriff aktivieren.",
                        "Erst mit Überwachungsmodus starten, dann auf 'Aktiviert'."
                    },
                    Source = "Get-MpPreference"
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
        Id = "system.controlledfolderaccess", Title = "Ransomware-Schutz", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = "Ransomware-Schutz-Status nicht abfragbar.",
        Explanation = "Prüfe in der Windows-Sicherheit unter Virus- und Bedrohungsschutz.",
        Source = "Get-MpPreference"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
