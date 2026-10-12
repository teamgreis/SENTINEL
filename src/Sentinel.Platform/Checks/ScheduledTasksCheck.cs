using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft geplante Aufgaben auf ungewöhnliche/potenziell schädliche Muster.</summary>
public sealed class ScheduledTasksCheck : ICheck
{
    public string Id => "persistence.tasks";
    public string Title => "Geplante Aufgaben";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft geplante Aufgaben auf auffällige Muster (Temp-Ordner, versteckte Namen, System-Kontext).";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.TaskPath -notlike '\\Microsoft*'} | ForEach-Object { $i = $_ | Select-Object TaskName,TaskPath,State; $a = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue; [PSCustomObject]@{TaskName=$i.TaskName; TaskPath=$i.TaskPath; Execute=(($_ | Select-Object -ExpandProperty Actions -ErrorAction SilentlyContinue | Select-Object -First 1).Execute)} } | ConvertTo-Json -Compress -Depth 3",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 })
                return Unknown("Geplante Aufgaben konnten nicht gelesen werden.");

            var suspicious = TaskAnalyzer.Analyze(output);

            if (suspicious.Count == 0)
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Keine auffälligen geplanten Aufgaben gefunden.",
                    Explanation = "Geplante Aufgaben sind ein klassischer Malware-Persistenz-Weg. Deine Nicht-Microsoft-Aufgaben zeigen keine der geprüften Warnmuster.",
                    Limitations = "Prüft nur Muster (Pfade, Namen), nicht die Signatur der ausgeführten Programme.",
                    Source = "Get-ScheduledTask"
                };

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Warning,
                Detail = $"{suspicious.Count} Aufgabe(n) mit auffälligen Merkmalen.",
                Explanation = "Manche Aufgaben laufen aus ungewöhnlichen Orten oder mit fragwürdigen Namen. Das muss nicht schädlich sein – aber prüfe die Liste genau.",
                RecommendedActions = new[]
                {
                    "Aufgabenplanung öffnen (taskschd.msc).",
                    "Die gemeldeten Aufgaben prüfen – kennst du sie alle?",
                    "Unbekannte Aufgaben mit verdächtigen Pfaden: Rechtsklick → Deaktivieren, dann beobachten."
                }.Concat(suspicious.Take(5).Select(s => $"• {s}")).ToArray(),
                Limitations = "Musterbasierte Prüfung – keine Signaturprüfung, keine Verhaltensanalyse.",
                Source = "Get-ScheduledTask"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("Geplante Aufgaben konnten nicht geprüft werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "persistence.tasks",
        Title = "Geplante Aufgaben",
        Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Prüfe manuell: Aufgabenplanung (taskschd.msc) → Aufgaben außerhalb des Microsoft-Ordners durchsehen.",
        Source = "Get-ScheduledTask"
    };
}
