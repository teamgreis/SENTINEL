using System.Runtime.InteropServices;
using Windows.Security.Credentials.UI;

namespace Sentinel.Platform.Users;

/// <summary>
/// Windows Hello: PIN, Fingerabdruck, Gesichtserkennung.
/// Nutzt die WinRT UserConsentVerifier-API – der Systemdialog erscheint
/// und das Ergebnis ist nur true/false (das Biometrie-Muster verlässt nie den TPM).
/// </summary>
public sealed class WindowsHelloAuthentication : Sentinel.Core.Users.IAuthenticationMethod
{
    private readonly bool _availabilityChecked;
    private readonly bool _isAvailable;

    public WindowsHelloAuthentication()
    {
        try
        {
            var status = UserConsentVerifier.CheckAvailabilityAsync().GetAwaiter().GetResult();
            _isAvailable = status == UserConsentVerifierAvailability.Available;
            _availabilityChecked = true;
        }
        catch
        {
            _isAvailable = false;
            _availabilityChecked = true;
        }
    }

    public string DisplayName => "Windows Hello (PIN / Biometrie)";

    public bool IsAvailable => _isAvailable;

    public string Instruction => _isAvailable
        ? "Windows-Hello-Dialog bestätigen (PIN, Fingerabdruck oder Gesicht)."
        : "Windows Hello ist auf diesem Gerät nicht eingerichtet.";

    /// <summary>
    /// Öffnet den Windows-Hello-Systemdialog. Gibt true zurück bei Erfolg.
    /// </summary>
    public async Task<bool> AuthenticateAsync(string promptMessage, CancellationToken ct = default)
    {
        if (!_isAvailable) return false;

        try
        {
            var result = await UserConsentVerifier.RequestVerificationAsync(promptMessage).AsTask(ct).ConfigureAwait(false);
            return result == UserConsentVerificationResult.Verified;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return false;
        }
    }
}
