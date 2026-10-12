using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft den Defender-Tamper-Schutz. Read-only.</summary>
public sealed class DefenderTamperCheck : ICheck
{
    public string Id => "defender.tamperprotection";
    public string Title => "Defender-Manipulationsschutz";
    public CheckWeight Weight => CheckWeight.High;
    public string Description => "Prüft, ob der Tamper-Schutz aktiv ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "try { (Get-MpPreference).DisableRealtimeMonitoring } catch { 'nicht abfragbar' }",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();

            if (combined.Contains("nicht abfragbar"))
                return Unknown();

            if (combined.Contains("True") || combined.Contains("true"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Fail,
                    Detail = "Echtzeitschutz ist deaktiviert.",
                    Explanation = "Ohne Echtzeitschutz prüft Defender Dateien nicht beim Öffnen. Schadsoftware kann ungehindert laufen. Wenn du das nicht selbst ausgeschaltet hast, ist das ein Warnsignal — manche Schadprogramme tun genau das.",
                    RecommendedActions = new[]
                    {
                        "Windows-Sicherheit → Viren- & Bedrohungsschutz → Einstellungen verwalten → Echtzeitschutz aktivieren.",
                        "Wenn es sich nicht einschalten lässt: verdächtige Programme prüfen, evtl. im abgesicherten Modus."
                    },
                    Source = "Get-MpPreference"
                };
            }

            // Tamper-Schutz-Zustand prüfen
            var (tp, _) = await PowerShell.RunAsync(
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Features' -ErrorAction SilentlyContinue).TamperProtection",
                ct).ConfigureAwait(false);

            if (tp.Trim() == "1" || tp.Contains("1"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Echtzeitschutz aktiv, Tamper-Schutz eingeschaltet.",
                    Explanation = "Der Manipulationsschutz hindert andere Programme daran, Defender auszuhebeln — auch mit Admin-Rechten. Das ist eine der stärksten Schutzschichten in Windows.",
                    Source = "Get-MpPreference + Registry"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Warning,
                Detail = "Echtzeitschutz aktiv, Tamper-Schutz aber nicht bestätigt.",
                Explanation = "Der Manipulationsschutz lässt sich nur über die Windows-Sicherheit umschalten. Prüfe ihn dort — er verhindert, dass Schadsoftware Defender abschaltet.",
                RecommendedActions = new[]
                {
                    "Windows-Sicherheit → Viren- & Bedrohungsschutz → Einstellungen verwalten → Manipulationsschutz."
                },
                Source = "Get-MpPreference"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown() => new()
    {
        Id = "defender.tamperprotection", Title = "Defender-Manipulationsschutz", Weight = CheckWeight.High,
        Status = CheckStatus.Unknown,
        Detail = "Defender-Status nicht abfragbar.",
        Explanation = "Prüfe in der Windows-Sicherheit, ob Echtzeitschutz und Manipulationsschutz aktiv sind.",
        Source = "Get-MpPreference"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
