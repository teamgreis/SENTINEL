using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft, ob die Windows-Sandbox verfügbar/aktiviert ist. Read-only.</summary>
public sealed class WindowsSandboxCheck : ICheck
{
    public string Id => "system.sandbox";
    public string Title => "Windows-Sandbox";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft, ob die Sandbox-Funktion aktiviert ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "try { Get-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' | Select-Object -ExpandProperty State } catch { 'nicht verfügbar' }",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();

            if (combined.Contains("nicht verfügbar") || combined.Contains("not available"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Info,
                    Detail = "Windows-Sandbox ist auf diesem System nicht verfügbar (oder nicht abfragbar).",
                    Explanation = "Die Sandbox öffnet ein wegwerfbares Windows-Fenster — ideal, um verdächtige Programme zu testen, ohne den echten PC zu gefährden. Nicht jede Windows-Edition und nicht jede Hardware unterstützt sie.",
                    RecommendedActions = new[]
                    {
                        "Windows Pro/Enterprise: Systemsteuerung → Programme → Windows-Funktionen → Windows-Sandbox aktivieren."
                    },
                    Source = "Get-WindowsOptionalFeature"
                };
            }

            if (combined.Contains("Enabled") || combined.Contains("1"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Windows-Sandbox ist aktiviert.",
                    Explanation = "Du kannst verdächtige Dateien und Programme in einer isolierten Umgebung testen. Was in der Sandbox passiert, bleibt in der Sandbox.",
                    Source = "Get-WindowsOptionalFeature"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Info,
                Detail = "Windows-Sandbox ist verfügbar, aber nicht aktiviert.",
                Explanation = "Die Funktion ist vorhanden, aber aus. Zum Testen verdächtiger Programme wäre sie nützlich.",
                RecommendedActions = new[]
                {
                    "Systemsteuerung → Programme → Windows-Funktionen → Windows-Sandbox aktivieren."
                },
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
        Id = "system.sandbox", Title = "Windows-Sandbox", Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Die Sandbox gibt es nur in Windows Pro/Enterprise.",
        Source = "Get-WindowsOptionalFeature"
    };
}
