using Sentinel.Core.Checks;

namespace Sentinel.Platform.Checks;

/// <summary>Prüft die Verfügbarkeit von Windows Hello (PIN, Biometrie). Read-only.</summary>
public sealed class WindowsHelloAvailabilityCheck : ICheck
{
    public string Id => "system.helloavailability";
    public string Title => "Windows-Hello-Verfügbarkeit";
    public CheckWeight Weight => CheckWeight.Low;
    public string Description => "Prüft, ob Windows Hello eingerichtet ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        try
        {
            var (output, error) = await PowerShell.RunAsync(
                "$p = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\PasswordLess\\Device'; " +
                "if (Test-Path $p) { (Get-ItemProperty $p).DevicePasswordLessBuildVersion } else { 'nicht eingerichtet' }",
                ct).ConfigureAwait(false);

            string combined = (output + " " + error).Trim();

            if (combined.Contains("nicht eingerichtet") || combined.Length == 0)
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Info,
                    Detail = "Windows Hello ist nicht eingerichtet.",
                    Explanation = "Ohne Windows Hello musst du für jede Anmeldung ein Passwort tippen. Mit Hello genügen PIN, Gesicht oder Fingerabdruck — bequemer und oft stärker, weil es an die Hardware gebunden ist.",
                    RecommendedActions = new[]
                    {
                        "Einstellungen → Konten → Anmeldeoptionen → Windows Hello."
                    },
                    Source = "Registry (PasswordLess)"
                };
            }

            return new CheckResult
            {
                Id = Id, Title = Title, Weight = Weight,
                Status = CheckStatus.Pass,
                Detail = "Windows Hello ist eingerichtet.",
                Explanation = "PIN, Gesicht oder Fingerabdruck stehen zur Verfügung. Die PIN ist an dieses Gerät gebunden und lässt sich nicht einfach aus der Ferne abgreifen.",
                Source = "Registry (PasswordLess)"
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Unknown(ex.Message);
        }
    }

    private static CheckResult Unknown(string msg) => new()
    {
        Id = "system.helloavailability", Title = "Windows-Hello-Verfügbarkeit", Weight = CheckWeight.Low,
        Status = CheckStatus.Unknown, Detail = msg,
        Explanation = "Prüfe unter Einstellungen → Konten → Anmeldeoptionen.",
        Source = "Registry (PasswordLess)"
    };
}
