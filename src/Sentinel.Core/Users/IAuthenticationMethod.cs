namespace Sentinel.Core.Users;

/// <summary>
/// Abstraktion über die Anmeldearten. Implementiert wird:
/// - Passwort (immer verfügbar)
/// - Windows Hello PIN/Biometrie (Windows, über WinRT UserConsentVerifier)
/// - Backup-Code (Wiederherstellung)
/// </summary>
public interface IAuthenticationMethod
{
    /// <summary>Anzeigename für die UI.</summary>
    string DisplayName { get; }

    /// <summary>Ist diese Methode auf diesem Gerät verfügbar?</summary>
    bool IsAvailable { get; }

    /// <summary>Kurzer Hinweis, was der Nutzer tun muss.</summary>
    string Instruction { get; }

    /// <summary>Führt die Authentifizierung aus (z. B. öffnet den Hello-Dialog).</summary>
    Task<bool> AuthenticateAsync(string promptMessage, CancellationToken ct = default);
}

/// <summary>
/// Passwort-Anmeldung – die Basis-Methode.
/// </summary>
public sealed class PasswordAuthentication : IAuthenticationMethod
{
    public string DisplayName => "Passwort";
    public bool IsAvailable => true;
    public string Instruction => "Passwort eingeben.";

    public Task<bool> AuthenticateAsync(string promptMessage, CancellationToken ct = default)
        => Task.FromResult(true); // Passwort-Eingabe wird von der UI selbst gemacht
}
