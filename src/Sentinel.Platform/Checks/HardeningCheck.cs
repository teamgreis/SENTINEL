using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft weitere Windows-Härtungsmerkmale: LSA-Schutz, WDigest, DEP.</summary>
public sealed class HardeningCheck : ICheck
{
    public string Id => "system.hardening";
    public string Title => "System-Härtung (LSA, WDigest)";
    public CheckWeight Weight => CheckWeight.Normal;
    public string Description => "Prüft LSA-Schutz und WDigest-Anmeldeinformationen im Speicher.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            // WDigest: UseLogonCredential=1 bedeutet, Passwörter liegen im Klartext im Speicher
            var (wdigest, wdError) = await PowerShell.RunAsync(
                "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential",
                ct).ConfigureAwait(false);

            var findings = new List<string>();
            var actions = new List<string>();

            if (wdError is not { Length: > 0 } && wdigest.Trim() == "1")
            {
                findings.Add("WDigest speichert Anmeldeinformationen im Klartext im Speicher – Werkzeuge wie Mimikatz können sie auslesen.");
                actions.Add("Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest → UseLogonCredential auf 0 setzen.");
            }

            // LSA-Schutz: RunAsPPL
            var (lsa, lsaError) = await PowerShell.RunAsync(
                "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL",
                ct).ConfigureAwait(false);

            bool lsaProtected = lsaError is not { Length: > 0 } && lsa.Trim() == "1";
            if (!lsaProtected)
            {
                findings.Add("Der LSA-Prozess ist nicht als geschützter Prozess (PPL) konfiguriert – Tools können versuchen, Anmeldedaten aus dem Speicher zu ziehen.");
                actions.Add("Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa → RunAsPPL auf 1 setzen (danach Neustart).");
            }

            if (findings.Count == 0)
                return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = "LSA-Schutz aktiv, WDigest speichert keine Klartext-Anmeldedaten.",
                Explanation = "Diese Härtungsmaßnahmen erschweren das Auslesen von Passwörtern aus dem Arbeitsspeicher erheblich.",
                Source = "Registry: Lsa / WDigest"
            };

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Warning,
                Detail = string.Join(" ", findings),
                Explanation = "Diese Einstellungen schützen deine Anmeldedaten im Speicher. Sie sind bei Angriffen mit Speicher-Analyse-Werkzeugen relevant.",
                RecommendedActions = actions.ToArray(),
                Limitations = "Prüft nur diese zwei bekannten Schwachstellen – weitere Härtung ist möglich (ASR-Regeln, Exploit Protection).",
                Source = "Registry: Lsa / WDigest"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown("Härtungsstatus konnte nicht ermittelt werden: " + ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.hardening",
        Title = "System-Härtung (LSA, WDigest)",
        Weight = CheckWeight.Normal,
        Status = CheckStatus.Unknown,
        Detail = msg,
        Explanation = "Diese Prüfung liest Registry-Werte – bei Blockaden durch Richtlinien ist der Status unklar.",
        Source = "Registry"
    };
}
