namespace Sentinel.Core.Users;

/// <summary>Rolle eines Nutzers im Sentinel-System.</summary>
public enum UserRole
{
    /// <summary>Darf alles: Nutzer verwalten, Einstellungen, Deinstallation freigeben.</summary>
    Admin,

    /// <summary>Darf prüfen und Berichte sehen, aber nicht verwalten.</summary>
    User
}
