using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft Secure Boot (UEFI). Read-only über Confirm-SecureBootUEFI.</summary>
public sealed class SecureBootCheck : ICheck
{
    public string Id => "system.secureboot";
    public string Title => "Secure Boot";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob Secure Boot aktiv ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "if (Confirm-SecureBootUEFI) { 'an' } else { 'aus' }", ct).ConfigureAwait(false);

            string combined = (output + " " + error).ToLowerInvariant();

            if (combined.Contains("aus") || combined.Contains("off") || combined.Contains("false"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Fail,
                    Detail = "Secure Boot ist deaktiviert.",
                    Explanation = "Ohne Secure Boot kann Schadsoftware die Bootkette infiltrieren und starten, bevor Windows selbst geladen ist (Bootkits).",
                    RecommendedActions = new[]
                    {
                        "PC neu starten → ins BIOS/UEFI (Entf/F2/F10).",
                        "Secure Boot auf 'Enabled' stellen, speichern, neu starten."
                    },
                    Source = "Confirm-SecureBootUEFI"
                };
            }

            if (combined.Contains("an") || combined.Contains("on") || combined.Contains("true"))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Secure Boot ist aktiv.",
                    Explanation = "Die Bootkette ist signaturgeschützt – nur signierte Bootloader dürfen starten.",
                    Source = "Confirm-SecureBootUEFI"
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
        Id = "system.secureboot", Title = "Secure Boot", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = "Secure-Boot-Status konnte nicht ermittelt werden.",
        Explanation = "Ältere PCs mit Legacy-BIOS haben kein Secure Boot. Prüfe im UEFI/BIOS unter 'Boot', ob die Option existiert.",
        Source = "Confirm-SecureBootUEFI"
    };

    private static CheckResult Unknown(string msg) => Unknown() with { Detail = msg };
}
