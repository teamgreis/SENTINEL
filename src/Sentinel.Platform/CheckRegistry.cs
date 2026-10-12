using Sentinel.Core.Checks;
using Sentinel.Platform.Checks;

namespace Sentinel.Platform;

/// <summary>Registriert alle Windows-Checks.</summary>
public static class CheckRegistry
{
    public static IReadOnlyList<ICheck> CreateDefault()
    {
        return new ICheck[]
        {
            // ---------- System (Basis) ----------
            new FirewallCheck(),
            new DefenderCheck(),
            new WindowsUpdateCheck(),
            new UacCheck(),
            new BitLockerCheck(),
            new ScriptHostCheck(),
            new SmartAppControlCheck(),
            new HardeningCheck(),

            // ---------- System (Runde 2) ----------
            new SecureBootCheck(),
            new TpmCheck(),
            new WindowsHelloCheck(),
            new ControlledFolderAccessCheck(),
            new AsrRulesCheck(),
            new DefenderSignatureAgeCheck(),
            new BitLockerRecoveryKeyCheck(),
            new PendingRebootCheck(),
            new UpdateOtherProductsCheck(),

            // ---------- Konten ----------
            new GuestAccountCheck(),
            new AutoLoginCheck(),
            new ScreenLockCheck(),
            new LockoutPolicyCheck(),
            new LocalAdminCountCheck(),
            new PasswordAgeCheck(),

            // ---------- Netzwerk ----------
            new NetworkProfileCheck(),
            new SmbV1Check(),
            new RemoteDesktopCheck(),
            new FirewallProfileCheck(),
            new DnsServerCheck(),
            new AdminShareCheck(),
            new WifiEncryptionCheck(),
            new SmbSigningCheck(),
            new TelnetFtpCheck(),

            // ---------- Startverhalten ----------
            new AutostartCheck(),

            // ---------- Persistenz & Verteidigung ----------
            new ScheduledTasksCheck(),
            new DefenderExclusionsCheck(),

            // ---------- Runde 3 (v2.3) ----------
            new ListeningPortsCheck(),
            new FileExtensionsCheck(),
            new SystemRestoreCheck(),
            new NtfsLastAccessCheck(),
            new RecoveryPartitionCheck(),
            new UpdatePauseCheck(),
            new FastStartupCheck(),
            new RdpNlaCheck(),

            // ---------- Runde 4 (v2.5) ----------
            new WindowsHelloAvailabilityCheck(),
            new DefenderTamperCheck(),
            new WindowsSandboxCheck(),
            new RecycleBinSizeCheck(),
            new WslStatusCheck()
        };
    }
}
