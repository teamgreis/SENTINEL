using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft Defender-Ausschlüsse – die werden gern von Malware gesetzt.</summary>
public sealed class DefenderExclusionsCheck : ICheck
{
    public string Id => "system.defender.exclusions";
    public string Title => "Defender-Ausschlüsse";
    public CheckWeight Weight => CheckWeight.High;
    public string Description => "Prüft, ob Pfade oder Prozesse vom Virenschutz ausgenommen sind.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$p = Get-MpPreference -ErrorAction SilentlyContinue; if ($p) { $p.ExclusionPath + $p.ExclusionProcess + $p.ExclusionExtension } | ConvertTo-Json -Compress",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 })
                return Unknown("Die Ausschluss-Liste konnte nicht gelesen werden (eventuell Rechte benötigt).");

            var exclusions = ExclusionsParser.Parse(output);

            if (exclusions.Count == 0)
                return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = "Keine Defender-Ausschlüsse konfiguriert.",
                Explanation = "Der Virenschutz prüft alle Pfade und Prozesse. Das ist der empfohlene Zustand.",
                Source = "Get-MpPreference"
            };

            // Ausschlüsse im Temp-Ordner oder für interpreter sind hochverdächtig
            var dangerous = exclusions.Where(x =>
                x.Contains("\\temp", StringComparison.OrdinalIgnoreCase) ||
                x.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                x.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase)).ToList();

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = dangerous.Count > 0 ? CheckStatus.Fail : CheckStatus.Warning,
                Detail = dangerous.Count > 0
                    ? $"{dangerous.Count} hochverdächtige Ausschlüsse (u. a. Temp/Skript-Interpreter)."
                    : $"{exclusions.Count} Ausschlüsse konfiguriert.",
                Explanation = "Ausschlüsse schwächen den Virenschutz gezielt. Malware legt sich gern selbst in die Ausschlussliste – besonders Temp-Ordner und Interpreter sind ein Warnsignal.",
                RecommendedActions = new[]
                {
                    "Windows-Sicherheit → Viren- & Bedrohungsschutz → Einstellungen → Ausschlüsse verwalten.",
                    "Ausschlüsse, die du nicht kennst, entfernen."
                }.Concat(exclusions.Take(5).Select(x => $"• {x}")).ToArray(),
                Source = "Get-MpPreference"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("Defender-Ausschlüsse konnten nicht geprüft werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.defender.exclusions",
        Title = "Defender-Ausschlüsse",
        Weight = CheckWeight.High,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Prüfe manuell: Windows-Sicherheit → Viren- & Bedrohungsschutz → Ausschlüsse verwalten. Dort sollte idealerweise nichts stehen.",
        Source = "Get-MpPreference"
    };
}
