using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft das TPM (Trusted Platform Module). Read-only über WMI.</summary>
public sealed class TpmCheck : ICheck
{
    public string Id => "system.tpm";
    public string Title => "TPM";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft, ob ein TPM-Chip vorhanden und aktiviert ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$t = Get-Tpm; if ($t) { \"$($t.TpmReady)|$($t.TpmEnabled)|$($t.ManufacturerIdTxt)\" } else { 'keins' }",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();
            if (combined.Contains("keins") || combined.Length == 0)
                return Unknown("Kein TPM gefunden.");

            var parts = combined.Split('|');
            bool ready = parts.Length > 0 && parts[0].Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            bool enabled = parts.Length > 1 && parts[1].Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            string vendor = parts.Length > 2 ? parts[2].Trim() : "";

            if (!enabled)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "Ein TPM ist vorhanden, aber nicht aktiviert.",
                    Explanation = "Das TPM sichert BitLocker-Schlüssel, Windows Hello und die Anmeldebestätigung. Ohne aktives TPM fehlt ein wichtiger Baustein.",
                    RecommendedActions = new[]
                    {
                        "PC neu starten → BIOS/UEFI → 'TPM Security Device' aktivieren.",
                        "Windows 11 benötigt ein TPM 2.0 – sonst kein Upgrade möglich."
                    },
                    Source = "Get-Tpm"
                };
            }

            if (ready)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = enabled && ready
                        ? $"TPM ist aktiv und bereit{(vendor.Length > 0 ? $" (Hersteller: {vendor})" : "")}."
                        : "TPM ist aktiv.",
                    Explanation = "Das TPM ist der sichere Schlüsselspeicher des PCs – Voraussetzung für BitLocker und Windows Hello.",
                    Source = "Get-Tpm"
                };
            }

            return Unknown("TPM vorhanden, aber nicht bereit.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.tpm", Title = "TPM", Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe im BIOS/UEFI unter 'Security', ob ein TPM vorhanden ist. Die meisten PCs seit 2014 haben eines.",
        Source = "Get-Tpm"
    };
}
