using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft die Autostart-Programme. Viele oder unbekannte Einträge
/// können Malware-Überreste oder Bremse sein. Read-only.
/// </summary>
public sealed class AutostartCheck : ICheck
{
    public string Id => "startup.programs";
    public string Title => "Autostart-Programme";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Zählt die Programme, die mit Windows automatisch starten.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -ErrorAction SilentlyContinue | Select-Object -Property * -ExcludeProperty PS* | ConvertTo-Json -Compress)",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 } && output.Length == 0)
                return Unknown("Die Autostart-Liste konnte nicht gelesen werden.");

            int count = AutostartParser.CountEntries(output);

            if (count > 10)
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = $"{count} Programme starten automatisch für alle Benutzer.",
                    Explanation = "Sehr viele Autostart-Programme verlangsamen den Start und vergrößern die Angriffsfläche. Unbekannte Einträge können Malware-Überreste sein.",
                    RecommendedActions = new[]
                    {
                        "Task-Manager → Autostart (Registerkarte „Startup-Apps“).",
                        "Unbekannte oder unnötige Einträge deaktivieren.",
                        "Einträge mit verdächtigen Pfaden (Temp-Ordner, zufällige Namen) genauer prüfen."
                    },
                    Limitations = "Zählt nur die systemweiten Einträge, nicht die pro Benutzer (HKCU\\...\\Run).",
                    Source = "Registry: HKLM\\...\\Run"
                };

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = $"{count} Programme starten automatisch für alle Benutzer.",
                Explanation = "Die Anzahl ist im normalen Rahmen. Prüfe gelegentlich, ob alle Einträge dir bekannt sind.",
                RecommendedActions = new[]
                {
                    "Task-Manager → Autostart: unbekannte Einträge deaktivieren."
                },
                Limitations = "Zählt nur die systemweiten Einträge, nicht die pro Benutzer (HKCU\\...\\Run).",
                Source = "Registry: HKLM\\...\\Run"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("Autostart-Status konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "startup.programs",
        Title = "Autostart-Programme",
        Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Prüfe manuell: Task-Manager → Autostart.",
        Source = "Registry"
    };
}
