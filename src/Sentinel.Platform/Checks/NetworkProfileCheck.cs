using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft das aktive Netzwerkprofil. „Öffentlich“ bedeutet reduzierte
/// Freigaben – empfohlen für fremde Netze (Café, Hotel).
/// </summary>
public sealed class NetworkProfileCheck : ICheck
{
    public string Id => "network.profile";
    public string Title => "Netzwerkprofil";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft, ob das aktive Netzwerk als öffentlich oder privat klassifiziert ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "Get-NetConnectionProfile | Select-Object Name,NetworkCategory | ConvertTo-Json -Compress",
                ct).ConfigureAwait(false);

            if (error is { Length: > 0 })
                return Unknown("Das Netzwerkprofil konnte nicht gelesen werden.");

            if (!NetworkProfileParser.TryParse(output, out var profiles) || profiles.Count == 0)
                return Unknown("Es wurde kein aktives Netzwerkprofil gefunden (keine Verbindung?).");

            bool anyPublic = profiles.Any(p => !p.IsPrivate);
            var names = string.Join(", ", profiles.Select(p => p.Name));

            if (anyPublic)
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Pass,
                    Detail = $"Aktives Netzwerk ({names}) ist als „Öffentlich“ klassifiziert.",
                    Explanation = "Im öffentlichen Modus ist dein PC für andere Geräte im Netzwerk nicht sichtbar – die richtige Wahl für fremde WLANs (Café, Hotel, Flughafen).",
                    Limitations = "Betrifft nur die Sichtbarkeit im lokalen Netz. Verschlüsselung und Firewall-Regeln werden separat geprüft.",
                    Source = "Get-NetConnectionProfile"
                };

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Warning,
                Detail = $"Aktives Netzwerk ({names}) ist als „Privat“ klassifiziert.",
                Explanation = "Im privaten Modus ist dein PC für andere Geräte im Netzwerk sichtbar und empfängt Freigaben. Das ist Zuhause sinnvoll – in fremden Netzen solltest du auf „Öffentlich“ umstellen.",
                RecommendedActions = new[]
                {
                    "Einstellungen → Netzwerk und Internet → WLAN/Ethernet → Netzwerkprofil.",
                    "In fremden Netzen auf „Öffentlich“ umstellen."
                },
                Limitations = "Nur relevant, wenn du dich in einem fremden oder öffentlichen Netzwerk befindest.",
                Source = "Get-NetConnectionProfile"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("Netzwerkprofil konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "network.profile",
        Title = "Netzwerkprofil",
        Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Prüfe manuell: Einstellungen → Netzwerk und Internet → aktuelles Netzwerk → Netzwerkprofil.",
        Source = "Get-NetConnectionProfile"
    };
}
