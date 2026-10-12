using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft, ob nach Inaktivität automatisch gesperrt wird.
/// Read-only Registry-Abfrage.
/// </summary>
public sealed class ScreenLockCheck : ICheck
{
    public string Id => "accounts.screenlock";
    public string Title => "Automatische Bildschirmsperre";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob der PC nach Inaktivität automatisch gesperrt wird.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            // Sekunden bis zum Sperren; 0 = sofort, -1/fehlend = nie
            var (output, error) = await PowerShell.RunAsync(
                "(Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveActive,ScreenSaveTimeOut -ErrorAction SilentlyContinue)",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 } && output.Length == 0)
                return Unknown("Die Bildschirmsperren-Einstellung konnte nicht gelesen werden.");

            // Versuche, die Werte zu extrahieren
            var (active, timeout) = ScreenLockParser.Parse(output);

            if (active != true || timeout is null or <= 0)
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "Es ist keine automatische Bildschirmsperre mit Zeitlimit konfiguriert.",
                    Explanation = "Ohne automatische Sperre bleibt der PC offen, wenn du ihn unbeaufsichtigt lässt. Jeder in Reichweite kann dann zugreifen.",
                    RecommendedActions = new[]
                    {
                        "Einstellungen → Personalisierung → Sperrbildschirm.",
                        "„Bildschirmschobereinstellungen“ → Wartezeit z. B. 10 Minuten, Haken bei „Anmeldeseite bei Reaktivierung“."
                    },
                    Source = "HKCU\\Control Panel\\Desktop"
                };

            int minutes = timeout.Value / 60;

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = $"Der PC wird nach {minutes} Minuten Inaktivität gesperrt.",
                Explanation = "Die automatische Sperre schützt deine Sitzung, wenn du den PC unbeaufsichtigt lässt.",
                Source = "HKCU\\Control Panel\\Desktop"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("Bildschirmsperren-Status konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "accounts.screenlock",
        Title = "Automatische Bildschirmsperre",
        Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Prüfe manuell: Einstellungen → Personalisierung → Sperrbildschirm → Bildschirmschon-Time-out.",
        Source = "HKCU\\Control Panel\\Desktop"
    };
}
