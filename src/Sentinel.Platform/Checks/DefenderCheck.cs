using Sentinel.Core.Checks;
using Sentinel.Core.System;

namespace Sentinel.Platform.Checks;

/// <summary>
/// Prüft den Virenschutz-Status über eine Kette von Strategien.
/// Jede Stufe ist read-only und funktioniert mit geringeren Rechten:
/// 1. WMI SecurityCenter2 (funktioniert praktisch immer, auch ohne Admin)
/// 2. Get-MpComputerStatus (präzise, braucht Admin)
/// 3. Defender-WMI-Provider direkt (root/Microsoft/Windows/Defender)
/// 4. Dienstestatus WinDefend (letzter Ausweg)
/// </summary>
public sealed class DefenderCheck : ICheck
{
    public string Id => "system.defender";
    public string Title => "Microsoft Defender";
    public CheckWeight Weight => CheckWeight.High;
    public string Description => "Prüft, ob ein Virenschutz mit Echtzeitschutz aktiv ist.";

    public async Task<CheckResult> RunAsync(CancellationToken ct = default)
    {
        var attempts = new List<string>();

        // Strategie 1: WMI SecurityCenter2 – zuerst, weil sie fast immer funktioniert
        var (wmiOutput, wmiError) = await PowerShell.RunAsync(
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState | ConvertTo-Json -Compress",
            ct).ConfigureAwait(false);

        if (wmiError is not { Length: > 0 } && WmiParser.TryParse(wmiOutput, out var products) && products.Count > 0)
        {
            return EvaluateWmi(products);
        }
        attempts.Add("SecurityCenter2 nicht nutzbar");

        // Strategie 2: Get-MpComputerStatus – präzise Werte (Admin)
        var (mpOutput, mpError) = await PowerShell.RunAsync(
            "(Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureAge | ConvertTo-Json -Compress)",
            ct).ConfigureAwait(false);

        if (mpError is not { Length: > 0 } && TryParse(mpOutput, out var mp))
        {
            return EvaluateMp(mp);
        }
        attempts.Add("Get-MpComputerStatus verweigert");

        // Strategie 3: Defender-WMI-Provider
        var (defWmiOutput, defWmiError) = await PowerShell.RunAsync(
            "Get-CimInstance -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AMRunningMode,RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress",
            ct).ConfigureAwait(false);

        if (defWmiError is not { Length: > 0 } && DefenderWmiParser.TryParse(defWmiOutput, out var dwmi))
        {
            if (dwmi.AntivirusEnabled)
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = dwmi.RealTimeProtectionEnabled ? CheckStatus.Pass : CheckStatus.Warning,
                    Detail = dwmi.RealTimeProtectionEnabled
                        ? "Microsoft Defender ist aktiv, einschließlich Echtzeitschutz."
                        : "Der Virenschutz ist aktiv, der Echtzeitschutz jedoch nicht.",
                    Explanation = dwmi.RealTimeProtectionEnabled
                        ? "Der Echtzeitschutz überwacht laufend auf bekannte Bedrohungen."
                        : "Ohne Echtzeitschutz werden neue Bedrohungen erst bei einer manuellen Prüfung erkannt.",
                    Limitations = "Kein Scanner erkennt alle Malware.",
                    Source = "Defender-WMI (root/Microsoft/Windows/Defender)"
                };

            attempts.Add("Defender-WMI meldet inaktiven Schutz");
        }
        else attempts.Add("Defender-WMI nicht nutzbar");

        // Strategie 4: Dienstestatus WinDefend
        var (svcOutput, svcError) = await PowerShell.RunAsync(
            "(Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status",
            ct).ConfigureAwait(false);

        if (svcError is not { Length: > 0 })
        {
            string status = svcOutput.Trim();
            if (status.Equals("Running", StringComparison.OrdinalIgnoreCase))
            {
                return new CheckResult
                {
                    Id = Id, Title = Title, Weight = Weight,
                    Status = CheckStatus.Warning,
                    Detail = "Der Defender-Dienst läuft, Details sind aber nicht abrufbar.",
                    Explanation = "Der Dienst läuft – ob Echtzeitschutz und Signaturen aktuell sind, konnte hier nicht geprüft werden.",
                    RecommendedActions = new[]
                    {
                        "Windows-Sicherheit → Viren- & Bedrohungsschutz öffnen und den grünen Status kontrollieren."
                    },
                    Limitations = "Nur Dienstestatus ermittelbar; Detailabfragen wurden verweigert.",
                    Source = "Get-Service WinDefend"
                };
            }
        }
        attempts.Add("Dienstestatus nicht nutzbar");

        // Nichts hat funktioniert – ehrliches Unknown statt Rätselraten
        return new CheckResult
        {
            Id = Id, Title = Title, Weight = Weight,
            Status = CheckStatus.Unknown,
            Detail = "Der Virenschutz-Status konnte auf diesem System nicht ermittelt werden.",
            Explanation = "Alle Abfragemethoden wurden verweigert oder sind nicht verfügbar. Das passiert manchmal, wenn Sicherheitsrichtlinien den Zugriff einschränken. Es sagt nichts darüber aus, ob dein Virenschutz tatsächlich funktioniert.",
            RecommendedActions = new[]
            {
                "Windows-Sicherheit öffnen (Start → „Windows-Sicherheit“).",
                "Dort „Viren- & Bedrohungsschutz“ kontrollieren – der Status dort ist maßgeblich, nicht unsere Prüfung."
            },
            Limitations = "Geprüfte Wege: " + string.Join("; ", attempts),
            Source = "Mehrere Methoden (alle erfolglos)"
        };
    }

    private static CheckResult EvaluateMp(MpStatus mp)
    {
        if (!mp.AntivirusEnabled)
            return new CheckResult
            {
                Id = "system.defender", Title = "Microsoft Defender", Weight = CheckWeight.High,
                Status = CheckStatus.Fail,
                Detail = "Microsoft Defender ist nicht aktiv.",
                Explanation = "Ohne aktiven Virenschutz können Schadprogramme unbemerkt ausgeführt werden. Hinweis: Wenn du eine andere Sicherheitssoftware nutzt, prüfe deren Status separat.",
                RecommendedActions = new[]
                {
                    "Windows-Sicherheit → Viren- & Bedrohungsschutz öffnen.",
                    "Prüfen, ob Defender oder ein anderes Programm aktiv ist."
                },
                Source = "Get-MpComputerStatus"
            };

        if (!mp.RealTimeProtectionEnabled)
            return new CheckResult
            {
                Id = "system.defender", Title = "Microsoft Defender", Weight = CheckWeight.High,
                Status = CheckStatus.Warning,
                Detail = "Der Virenschutz ist aktiv, der Echtzeitschutz jedoch nicht.",
                Explanation = "Ohne Echtzeitschutz werden neue Bedrohungen erst bei einer manuellen Prüfung erkannt.",
                RecommendedActions = new[]
                {
                    "Windows-Sicherheit → Viren- & Bedrohungsschutz → Einstellungen → Echtzeitschutz aktivieren."
                },
                Source = "Get-MpComputerStatus"
            };

        bool stale = mp.AntivirusSignatureAge is > 7;
        return new CheckResult
        {
            Id = "system.defender", Title = "Microsoft Defender", Weight = CheckWeight.High,
            Status = stale ? CheckStatus.Warning : CheckStatus.Pass,
            Detail = stale
                ? $"Defender ist aktiv, die Virensignaturen sind aber {mp.AntivirusSignatureAge} Tage alt."
                : "Microsoft Defender ist aktiv, einschließlich Echtzeitschutz.",
            Explanation = stale
                ? "Veraltete Signaturen erkennen neue Bedrohungen nicht zuverlässig."
                : "Der Echtzeitschutz überwacht laufend auf bekannte Bedrohungen. Ein guter Grundschutz – ergänzend zu sicheren Gewohnheiten.",
            RecommendedActions = stale
                ? new[] { "Windows-Sicherheit → Viren- & Bedrohungsschutz → „Nach Updates suchen“ ausführen." }
                : Array.Empty<string>(),
            Limitations = "Kein Scanner erkennt alle Malware. Unbekannte Bedrohungen können unentdeckt bleiben.",
            Source = "Get-MpComputerStatus"
        };
    }

    private static CheckResult EvaluateWmi(List<AvProduct> products)
    {
        var best = products
            .OrderByDescending(p => WmiStatusDecoder.IsRealtimeProtectionOn(p.ProductState))
            .ThenByDescending(p => WmiStatusDecoder.IsEnabled(p.ProductState))
            .First();

        string name = string.IsNullOrWhiteSpace(best.DisplayName) ? "Sicherheitssoftware" : best.DisplayName;

        if (!WmiStatusDecoder.IsEnabled(best.ProductState))
            return new CheckResult
            {
                Id = "system.defender", Title = "Microsoft Defender", Weight = CheckWeight.High,
                Status = CheckStatus.Warning,
                Detail = $"Erkannte Sicherheitssoftware: {name} – Status laut System: nicht aktiv.",
                Explanation = "Das System meldet eine Sicherheitssoftware, die aber nicht aktiv zu sein scheint. Prüfe deren Status direkt.",
                RecommendedActions = new[]
                {
                    "Programm öffnen und prüfen, ob der Schutz aktiv ist.",
                    "Falls nicht: Schutz aktivieren oder eine andere Sicherheitssoftware installieren."
                },
                Limitations = "Einschätzung basiert auf einem allgemeinen Windows-Statuswert, nicht auf Defender-Details.",
                Source = "WMI SecurityCenter2 (ohne Admin-Rechte ermittelt)"
            };

        if (!WmiStatusDecoder.IsRealtimeProtectionOn(best.ProductState))
            return new CheckResult
            {
                Id = "system.defender", Title = "Microsoft Defender", Weight = CheckWeight.High,
                Status = CheckStatus.Warning,
                Detail = $"{name} ist aktiv, der Echtzeitschutz ist aber laut Status aus.",
                Explanation = "Ohne Echtzeitschutz werden neue Bedrohungen erst bei einer manuellen Prüfung erkannt.",
                RecommendedActions = new[] { $"In {name} den Echtzeitschutz aktivieren." },
                Source = "WMI SecurityCenter2 (ohne Admin-Rechte ermittelt)"
            };

        bool sigsStale = WmiStatusDecoder.AreSignaturesStale(best.ProductState);

        return new CheckResult
        {
            Id = "system.defender", Title = "Microsoft Defender", Weight = CheckWeight.High,
            Status = sigsStale ? CheckStatus.Warning : CheckStatus.Pass,
            Detail = sigsStale
                ? $"{name} ist aktiv, die Virensignaturen sind aber veraltet."
                : $"{name} ist aktiv, einschließlich Echtzeitschutz.",
            Explanation = sigsStale
                ? "Veraltete Signaturen erkennen neue Bedrohungen nicht zuverlässig."
                : "Der Echtzeitschutz überwacht laufend auf bekannte Bedrohungen. Ein guter Grundschutz – ergänzend zu sicheren Gewohnheiten.",
            RecommendedActions = sigsStale
                ? new[] { $"{name} öffnen und „Nach Updates suchen“ ausführen." }
                : Array.Empty<string>(),
            Limitations = "Kein Scanner erkennt alle Malware. Unbekannte Bedrohungen können unentdeckt bleiben.",
            Source = "WMI SecurityCenter2 (ohne Admin-Rechte ermittelt)"
        };
    }

    private static bool TryParse(string json, out MpStatus status)
    {
        status = default!;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;
            status = new MpStatus
            {
                RealTimeProtectionEnabled = root.TryGetProperty("RealTimeProtectionEnabled", out var r) &&
                                             r.ValueKind == System.Text.Json.JsonValueKind.True,
                AntivirusEnabled = root.TryGetProperty("AntivirusEnabled", out var a) &&
                                   a.ValueKind == System.Text.Json.JsonValueKind.True,
                AntivirusSignatureAge = root.TryGetProperty("AntivirusSignatureAge", out var s) &&
                                        s.ValueKind == System.Text.Json.JsonValueKind.Number
                    ? s.GetInt32() : null
            };
            return true;
        }
        catch
        {
            return false;
        }
    }

    private sealed class MpStatus
    {
        public bool RealTimeProtectionEnabled { get; init; }
        public bool AntivirusEnabled { get; init; }
        public int? AntivirusSignatureAge { get; init; }
    }
}
