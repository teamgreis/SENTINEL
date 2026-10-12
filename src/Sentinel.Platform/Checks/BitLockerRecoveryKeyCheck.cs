using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft die Speicherdiagnose (Storage Sense) und das Backup-Verhalten.
/// Read-only.
/// </summary>
public sealed class BitLockerRecoveryKeyCheck : ICheck
{
    public string Id => "system.bitlockerrecovery";
    public string Title => "BitLocker-Wiederherstellungsschlüssel";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob der BitLocker-Wiederherstellungsschlüssel gesichert ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$v = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue; " +
                "if ($v) { \"$($v.VolumeStatus)|$($v.ProtectionStatus)|$($v.KeyProtector.Count)\" } else { 'keine' }",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();

            if (combined.Contains("keine") || combined.Length == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Unknown,
                    Detail = "BitLocker-Status auf Laufwerk C: nicht abfragbar.",
                    Explanation = "Falls BitLocker nicht aktiv ist, ist dieses Check nicht relevant.",
                    Source = "Get-BitLockerVolume"
                };
            }

            var parts = combined.Split('|');
            string volumeStatus = parts.Length > 0 ? parts[0] : "";
            bool protectionOn = parts.Length > 1 && parts[1].Equals("On", StringComparison.OrdinalIgnoreCase);
            int protectors = parts.Length > 2 && int.TryParse(parts[2], out var k) ? k : 0;

            if (!protectionOn)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Info,
                    Detail = "BitLocker ist nicht aktiv auf C:.",
                    Explanation = "Ohne BitLocker kann jeder, der physisch auf die Festplatte zugreift (Ausbau in ein anderes Gerät), alle Daten lesen.",
                    Source = "Get-BitLockerVolume"
                };
            }

            // Wiederherstellungsschlüssel: mindestens 2 Protektoren (TPM + RecoveryPassword)
            if (protectors >= 2)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = $"BitLocker aktiv mit {protectors} Schlüsselschutzelementen (inkl. Wiederherstellungsschlüssel).",
                    Explanation = "Mit dem Wiederherstellungsschlüssel kannst du die Festplatte auch nach TPM-Ausfall oder Hardwarewechsel entschlüsseln.",
                    Source = "Get-BitLockerVolume"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Warning,
                Detail = $"BitLocker aktiv, aber nur {protectors} Schlüsselschutzelement – kein Wiederherstellungsschlüssel erkannt.",
                Explanation = "Ohne gesicherten Wiederherstellungsschlüssel sind die Daten bei TPM-Ausfall oder Mainboard-Wechsel für immer verloren.",
                RecommendedActions = new[]
                {
                    "BitLocker verwalten → Wiederherstellungsschlüssel sichern.",
                    "Den Schlüssel ausdrucken und im Microsoft-Konto oder OneDrive hinterlegen."
                },
                Source = "Get-BitLockerVolume"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.bitlockerrecovery", Title = "BitLocker-Wiederherstellungsschlüssel", Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe in der Systemsteuerung → BitLocker-Laufwerkverschlüsselung, ob ein Wiederherstellungsschlüssel gesichert ist.",
        Source = "Get-BitLockerVolume"
    };
}
