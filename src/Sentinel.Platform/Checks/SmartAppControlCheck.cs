using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft den Zustand der Smart App Control und den Signaturstatus
/// der eigenen ausführbaren Datei. Erklärt Blockaden verständlich.
/// </summary>
public sealed class SmartAppControlCheck : ICheck
{
    public string Id => "system.smartappcontrol";
    public string Title => "Smart App Control";
    public CheckWeight Weight => CheckWeight.Low; // rein informativ – wird kaum ins Gewicht fallen
    public string Description => "Prüft den Zustand der Smart App Control und ob SENTINEL selbst signiert ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            // 1. SAC-Zustand: Get-MpPreference, Fallback Registry
            var (sacOutput, sacError) = await PowerShell.RunAsync(
                "(Get-MpPreference -ErrorAction SilentlyContinue).SmartAppControlState",
                ct).ConfigureAwait(false);

            var sacState = SacStateParser.FromOutput(sacOutput);

            if (sacState == SacState.Unknown)
            {
                var (regOutput, regError) = await PowerShell.RunAsync(
                    "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState",
                    ct).ConfigureAwait(false);

                if (regError is not { Length: > 0 })
                    sacState = SacStateParser.FromOutput(regOutput);
            }

            // 2. Signaturstatus der eigenen Exe
            string exePath = Environment.ProcessPath ?? "";
            var sigState = SignatureState.Unknown;
            string? sigRaw = null;
            if (!string.IsNullOrEmpty(exePath))
            {
                var (sigOutput, sigError) = await PowerShell.RunAsync(
                    $"(Get-AuthenticodeSignature '{exePath}' -ErrorAction SilentlyContinue).Status",
                    ct).ConfigureAwait(false);
                if (sigError is not { Length: > 0 })
                {
                    sigRaw = sigOutput.Trim();
                    sigState = SacStateParser.ParseSignatureStatus(sigRaw);
                }
            }

            // 3. Bewertung
            string sacDesc = SacStateParser.Describe(sacState);
            string sigDesc = sigState switch
            {
                SignatureState.Valid => "SENTINEL ist digital signiert.",
                SignatureState.NotSigned => "SENTINEL ist NICHT digital signiert.",
                SignatureState.Invalid => "Die Signatur von SENTINEL ist ungültig.",
                _ => "Der Signaturstatus von SENTINEL konnte nicht ermittelt werden."
            };

            if (sacState == SacState.Enforce && sigState is not SignatureState.Valid)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = $"Smart App Control ist {sacDesc}. {sigDesc}",
                    Explanation = "Smart App Control blockiert Komponenten ohne gültige Microsoft-Signatur – das ist der Grund, falls Teile von SENTINEL nicht laden. Die Blockade betrifft die unsignierten SENTINEL-Dateien; dein System ist dadurch nicht unsicherer.",
                    RecommendedActions = new[]
                    {
                        "SENTINEL-Einstellungen → diese Meldung enthält eine Signier-Anleitung (Ordner: SIGNIERUNG.md neben der Exe).",
                        "Oder: Windows-Sicherheit → App- und Browsersteuerung → Smart App Control-Einstellungen → auf „Warnen“ umstellen.",
                        "Wichtig: Das Umschalten aus „Aktiv“ ist EINMALIG – danach lässt sich Smart App Control nur durch eine Windows-Neuinstallation wieder einschalten."
                    },
                    Limitations = "Eine Selbstsignierung behebt SmartScreen-Warnungen, überzeugt aber Smart App Control im Modus „Aktiv“ nicht – dafür ist ein signiertes Zertifikat mit Microsoft-Reputation nötig.",
                    Source = $"Get-MpPreference / Registry CI-Policy / Get-AuthenticodeSignature (Signatur: {sigRaw ?? "?"})"
                };
            }

            if (sacState == SacState.Evaluation && sigState is not SignatureState.Valid)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = $"Smart App Control ist im {sacDesc}. {sigDesc}",
                    Explanation = "Im Testmodus werden Blockaden nur protokolliert, nicht durchgesetzt. Falls du SAC später auf „Aktiv“ stellst, würden die unsignierten SENTINEL-Dateien blockiert.",
                    RecommendedActions = new[]
                    {
                        "Falls SENTINEL dauerhaft laufen soll: Signier-Anleitung beachten (SIGNIERUNG.md) oder SAC auf „Warnen“ stellen.",
                        "Warnung: Das Verlassen des Testmodus bzw. das spätere Ausschalten ist EINMALIG."
                    },
                    Source = "Get-MpPreference / Get-AuthenticodeSignature"
                };
            }

            if (sacState == SacState.Off)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Info,
                    Detail = $"Smart App Control ist {sacDesc}. {sigDesc}",
                    Explanation = "Smart App Control ist aus – es findet keine Signaturprüfung statt. Defender und SmartScreen schützen weiterhin.",
                    Source = "Get-MpPreference / Registry"
                };
            }

            // Enforce + signiert, oder Evaluation + signiert
            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = $"Smart App Control ist {sacDesc}. {sigDesc}",
                Explanation = "Die Signaturprüfung ist aktiv und SENTINEL hat eine gültige Signatur – keine Blockaden zu erwarten.",
                Source = "Get-MpPreference / Get-AuthenticodeSignature"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("Smart App Control konnte nicht geprüft werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.smartappcontrol",
        Title = "Smart App Control",
        Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Der Zustand ließ sich nicht ermitteln. Prüfe manuell: Windows-Sicherheit → App- und Browsersteuerung → Smart App Control-Einstellungen.",
        Source = "Get-MpPreference"
    };
}
