using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft die UAC-Einstellung (Registry, read-only).</summary>
public sealed class UacCheck : ICheck
{
    public string Id => "system.uac";
    public string Title => "Benutzerkontensteuerung (UAC)";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob die Benutzerkontensteuerung aktiviert ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 } && output.Length == 0)
                return Unknown("UAC-Status konnte nicht gelesen werden.");

            if (string.IsNullOrWhiteSpace(output))
                return Unknown("UAC-Einstellung nicht gefunden.");

            bool enabled = output.Trim() == "1";

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = enabled ? CheckStatus.Pass : CheckStatus.Warning,
                Detail = enabled ? "Benutzerkontensteuerung ist aktiviert." : "Benutzerkontensteuerung ist deaktiviert.",
                Explanation = enabled
                    ? "Die UAC fragt nach Bestätigung, bevor Programme Systemänderungen vornehmen – ein wichtiger Schutz gegen unerwünschte Installationen."
                    : "Ohne UAC können Programme ohne Rückfrage Systemänderungen vornehmen. Das erhöht das Risiko durch Schadsoftware erheblich.",
                RecommendedActions = enabled ? Array.Empty<string>() : new[]
                {
                    "Systemsteuerung → Benutzerkonten → Einstellungen der Benutzerkontensteuerung ändern.",
                    "Regler auf die Standard- oder höhere Stufe stellen."
                },
                Source = "Registry: Policies\\System (EnableLUA)"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("UAC-Status konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.uac",
        Title = "Benutzerkontensteuerung (UAC)",
        Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Die UAC-Einstellung konnte nicht ausgelesen werden. Prüfe sie in den Windows-Einstellungen.",
        Source = "Registry"
    };
}
