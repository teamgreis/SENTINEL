using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft den WSL-Status (Angriffsfläche in virtuellen Linux-Umgebungen). Read-only.</summary>
public sealed class WslStatusCheck : ICheck
{
    public string Id => "system.wsl";
    public string Title => "WSL-Status";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft, ob das Windows-Subsystem für Linux installiert ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "try { (Get-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Windows-Subsystem-Linux').State } catch { 'nicht verfügbar' }",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();

            if (combined.Contains("nicht verfügbar") || combined.Length == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Info,
                    Detail = "WSL ist nicht installiert.",
                    Explanation = "Kein WSL, keine zusätzliche Angriffsfläche. Wenn du Linux unter Windows nicht brauchst, ist das der sicherste Zustand.",
                    Source = "Get-WindowsOptionalFeature"
                };
            }

            if (combined.Contains("Enabled") || combined.Contains("1"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Info,
                    Detail = "WSL ist aktiviert.",
                    Explanation = "Das Linux-Subsystem läuft. Das ist praktisch für Entwicklung, erweitert aber die Angriffsfläche: Linux-Werkzeuge und -Dateisysteme sind jetzt erreichbar. Halte die Linux-Distribution aktuell — Windows-Updates patchen WSL nicht automatisch mit.",
                    RecommendedActions = new[]
                    {
                        "Linux-Distribution aktuell halten: sudo apt update && sudo apt upgrade.",
                        "Nicht genutzte Distributionen entfernen (wsl --unregister)."
                    },
                    Source = "Get-WindowsOptionalFeature"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = "WSL ist vorhanden, aber deaktiviert.",
                Explanation = "Deaktiviert heißt: keine zusätzliche Angriffsfläche. Du kannst es bei Bedarf aktivieren.",
                Source = "Get-WindowsOptionalFeature"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.wsl", Title = "WSL-Status", Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe den WSL-Status mit: wsl --status.",
        Source = "Get-WindowsOptionalFeature"
    };
}
