using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft den BitLocker-Status des Systemlaufwerks über WMI.
/// Funktioniert ohne Admin-Rechte (reiner Lesezugriff).
/// </summary>
public sealed class BitLockerCheck : ICheck
{
    public string Id => "system.bitlocker";
    public string Title => "BitLocker-Laufwerksverschlüsselung";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob das Systemlaufwerk verschlüsselt ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            // ConversionStatus 1 = vollständig verschlüsselt, 0 = entschlüsselt
            var (output, error) = await PowerShell.RunAsync(
                "Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter \"DriveLetter='C:'\" -ErrorAction SilentlyContinue | Select-Object DriveLetter,ConversionStatus | ConvertTo-Json -Compress",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 } && output.Length == 0)
                return Unknown("BitLocker-Status konnte nicht gelesen werden (WMI-Zugriff verweigert).");

            if (string.IsNullOrWhiteSpace(output) || output is "null" or "[]")
                return Unknown("Keine BitLocker-Informationen für Laufwerk C: gefunden. BitLocker ist möglicherweise nicht verfügbar oder der Treiber fehlt (häufig auf PCs mit „Modern Standby“ oder bestimmter Hardware).");

            if (!EncryptionParser.TryParse(output, out var vol))
                return Unknown("BitLocker-Status konnte nicht interpretiert werden.");

            return vol.ConversionStatus switch
            {
                1 => new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = "Das Systemlaufwerk (C:) ist vollständig verschlüsselt.",
                    Explanation = "BitLocker schützt deine Daten, falls das Gerät gestohlen wird und die Festplatte ausgebaut wird. Ohne Schlüssel sind die Daten nicht lesbar.",
                    Limitations = "Schützt nur im ausgeschalteten Zustand gegen physischen Zugriff – nicht gegen laufende Malware oder Kontodiebstahl.",
                    Source = "WMI Win32_EncryptableVolume"
                },
                0 => new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "Das Systemlaufwerk (C:) ist nicht verschlüsselt.",
                    Explanation = "Ohne Laufwerksverschlüsselung können bei Diebstahl des Geräts alle Daten direkt ausgelesen werden.",
                    RecommendedActions = new[]
                    {
                        "Einstellungen → Datenschutz und Sicherheit → Geräteverschlüsselung (oder BitLocker).",
                        "Wichtig: Wiederherstellungsschlüssel sichern (Microsoft-Konto oder Ausdruck) – ohne ihn sind die Daten bei Problemen verloren."
                    },
                    Source = "WMI Win32_EncryptableVolume"
                },
                _ => new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = $"Das Systemlaufwerk wird gerade ver-/entschlüsselt (Status {vol.ConversionStatus}).",
                    Explanation = "Der Vorgang läuft noch. Bis er abgeschlossen ist, ist das Laufwerk nicht vollständig geschützt.",
                    RecommendedActions = new[]
                    {
                        "Gerät am Netz lassen, bis der Vorgang abgeschlossen ist."
                    },
                    Source = "WMI Win32_EncryptableVolume"
                }
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("BitLocker-Status konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.bitlocker",
        Title = "BitLocker-Laufwerksverschlüsselung",
        Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "BitLocker ließ sich nicht prüfen. Prüfe es manuell unter Einstellungen → Datenschutz und Sicherheit → Geräteverschlüsselung.",
        Source = "WMI Win32_EncryptableVolume"
    };
}
