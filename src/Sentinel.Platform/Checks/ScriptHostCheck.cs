using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft, ob der Windows Script Host aktiv ist. WSH kann .vbs/.js ausführen –
/// bei deaktiviertem Zustand scheitert ein großer Teil der Malware-Ausführung.
/// Read-only Registry-Abfrage.
/// </summary>
public sealed class ScriptHostCheck : ICheck
{
    public string Id => "system.scripthost";
    public string Title => "Windows Script Host";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob .vbs/.js-Dateien über den Windows Script Host ausgeführt werden können.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            // Enabled = 0 bedeutet deaktiviert (empfohlen), 1 = aktiv
            var (output, error) = await PowerShell.RunAsync(
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -Name Enabled -ErrorAction SilentlyContinue).Enabled",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 } && output.Length == 0)
                return Unknown("Die Script-Host-Einstellung konnte nicht gelesen werden.");

            if (string.IsNullOrWhiteSpace(output))
                return Unknown("Keine Richtlinie gefunden – der Standard ist aktiv.");

            bool enabled = output.Trim() == "1";

            if (enabled)
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "Der Windows Script Host ist aktiv.",
                    Explanation = "Über den Script Host lassen sich .vbs- und .js-Dateien ausführen – ein bei Malware beliebter Weg. Wenn du keine eigenen Skripte nutzt, kannst du ihn gefahrlos deaktivieren.",
                    RecommendedActions = new[]
                    {
                        "Windows-Taste + R → „regedit“.",
                        "Zu HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings navigieren.",
                        "Wert „Enabled“ auf 0 setzen (erstellt ihn als DWORD, falls er fehlt)."
                    },
                    Limitations = "Betrifft nur die systemweite Einstellung, nicht benutzerspezifische Richtlinien.",
                    Source = "Registry: Windows Script Host\\Settings"
                };

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = "Der Windows Script Host ist deaktiviert.",
                Explanation = "Ohne Script Host können .vbs/.js-Anhänge keine Aktionen auslösen. Das blockiert eine verbreitete Malware-Methode.",
                Limitations = "Wenn du eigene Skripte nutzt, müssen diese auf anderen Wegen laufen (z. B. cscript mit bewusstem Aufruf).",
                Source = "Registry: Windows Script Host\\Settings"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("Script-Host-Status konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.scripthost",
        Title = "Windows Script Host",
        Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Prüfe manuell in der Registry: HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings → Enabled (0 = aus).",
        Source = "Registry"
    };
}
