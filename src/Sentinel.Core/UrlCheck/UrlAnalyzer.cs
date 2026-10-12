using System.Text;
using NetIPAddress = System.Net.IPAddress;

namespace Sentinel.Core.UrlCheck;

/// <summary>
/// Prüft URLs auf klar definierte Risikosignale – rein offline und deterministisch.
/// Kein Scanner erkennt jede Phishing-Seite; dieses Modul deckt nur dokumentierte
/// Signale ab (irreführende Schreibweisen, verdächtige Struktur, Tricks).
/// </summary>
public sealed class UrlAnalyzer
{
    // Bekannte Marken, deren Schreibweise gern imitiert wird (kleine Auswahl, erweiterbar).
    private static readonly string[] ProtectedBrands =
    {
        "microsoft", "paypal", "amazon", "google", "apple", "sparkasse",
        "dhl", "postbank", "ing", "commerzbank", "vodafone", "telekom", "netflix"
    };

    private static readonly string[] SuspiciousTlds =
    {
        ".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz", ".rest"
    };

    private static readonly char[] HomoglyphSuspects =
    {
        'а', 'е', 'о', 'р', 'с', 'х', // kyrillisch
        'ο', 'α' // griechisch
    };

    public UrlReport Analyze(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return new UrlReport
            {
                Input = url ?? string.Empty,
                Verdict = UrlVerdict.Invalid,
                Summary = "Keine URL angegeben.",
                Findings = new List<UrlFinding>()
            };
        }

        var findings = new List<UrlFinding>();

        string trimmed = url.Trim();
        if (!trimmed.Contains("://", StringComparison.Ordinal))
            trimmed = "http://" + trimmed;

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return new UrlReport
            {
                Input = url,
                Verdict = UrlVerdict.Invalid,
                Summary = "Die Eingabe ist keine gültige http(s)-Adresse.",
                Findings = new List<UrlFinding>()
            };
        }

        string host = uri.Host.ToLowerInvariant();
        string pathAndQuery = uri.PathAndQuery;

        // 1. Kein HTTPS
        if (uri.Scheme == Uri.UriSchemeHttp)
        {
            findings.Add(new UrlFinding
            {
                Severity = Severity.Medium,
                Title = "Keine verschlüsselte Verbindung (kein HTTPS)",
                Description = "Die Seite überträgt Daten unverschlüsselt. sensible Eingaben sollten nur auf HTTPS-Seiten erfolgen."
            });
        }

        // 2. Verdächtige TLD
        foreach (var tld in SuspiciousTlds)
        {
            if (host.EndsWith(tld, StringComparison.Ordinal))
            {
                findings.Add(new UrlFinding
                {
                    Severity = Severity.Medium,
                    Title = "Ungewöhnliche Domain-Endung",
                    Description = $"Die Endung „{tld}“ wird überdurchschnittlich oft für Phishing und Wegwerf-Domains genutzt."
                });
                break;
            }
        }

        // 3. IP-Adresse statt Domainname
        if (NetIPAddress.TryParse(host, out _))
        {
            findings.Add(new UrlFinding
            {
                Severity = Severity.High,
                Title = "IP-Adresse statt Domainname",
                Description = "Seriöse Anbieter nutzen Namen, keine rohen IP-Adressen. Häufiges Phishing-Muster."
            });
        }

        // 4. Homoglyphen / nicht-lateinische Zeichen im Host
        if (host.Any(HomoglyphSuspects.Contains))
        {
            findings.Add(new UrlFinding
            {
                Severity = Severity.High,
                Title = "Täuschend ähnliche Buchstaben (Homoglyphen)",
                Description = "Die Adresse enthält Zeichen aus anderen Alphabeten, die lateinischen Buchstaben zum Verwechseln ähneln – klassische Phishing-Technik."
            });
        }

        // 5. Marken-Imitate: Domain besteht (fast) nur aus einer Marke mit Ziffernersatz,
        //    oder Marke erscheint außerhalb der echten Hauptdomain
        var labels = host.Split('.');
        foreach (var brand in ProtectedBrands)
        {
            // a) Ziffernersatz direkt in einem Label: paypa1.de, micr0soft.com
            string? impostor = labels.FirstOrDefault(l => IsOneCharDigitVariant(l, brand));
            if (impostor is not null)
            {
                findings.Add(new UrlFinding
                {
                    Severity = Severity.High,
                    Title = "Mögliche Imitation durch Ziffernersatz",
                    Description = $"Die Domain ähnelt „{brand}“, nutzt aber eine Ziffer anstelle eines Buchstabens – typische Fälschung."
                });
                continue;
            }

            // b) Marke nur als Subdomain/Präfix, nicht als echte Hauptdomain
            if (!host.Contains(brand, StringComparison.Ordinal))
                continue;

            bool brandIsSecondLevel = labels.Length >= 2 && labels[^2].Equals(brand, StringComparison.Ordinal);
            if (!brandIsSecondLevel)
            {
                findings.Add(new UrlFinding
                {
                    Severity = Severity.High,
                    Title = $"Markenname außerhalb der echten Domain ({brand})",
                    Description = $"„{brand}“ erscheint nicht als Hauptdomain, sondern in einem anderen Teil der Adresse. Beispiel für irreführende Weiterleitungen."
                });
            }
        }

        // 6. Sehr lange Hosts / @-Trick / viele Subdomains
        int dots = host.Count(c => c == '.');
        if (dots >= 4)
        {
            findings.Add(new UrlFinding
            {
                Severity = Severity.Low,
                Title = "Ungewöhnlich viele Subdomains",
                Description = "Viele Verschachtelungsebenen können verschleiern, welche Domain wirklich aufgerufen wird."
            });
        }
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            findings.Add(new UrlFinding
            {
                Severity = Severity.High,
                Title = "@-Trick in der Adresse",
                Description = $"Der Teil „{uri.UserInfo}“ vor dem @ gehört nicht zur aufgerufenen Domain. Häufig genutzt, um echte Domains vorzutäuschen – tatsächlich aufgerufen wird: " + uri.Host + "."
            });
        }

        // 7. Verdächtige Weiterleitungs-Parameter
        foreach (var p in new[] { "redirect=", "url=", "next=", "return=", "goto=" })
        {
            if (pathAndQuery.Contains(p, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new UrlFinding
                {
                    Severity = Severity.Low,
                    Title = "Weiterleitungs-Parameter erkannt",
                    Description = "Die URL enthält einen Parameter, der auf eine andere Seite weiterleitet. Das Ziel vor dem Klicken prüfen."
                });
                break;
            }
        }

        // 8. Punycode (xn--) bei bekannter Marke
        if (host.Contains("xn--", StringComparison.Ordinal))
        {
            findings.Add(new UrlFinding
            {
                Severity = Severity.Medium,
                Title = "Punycode-Kodierung (xn--)",
                Description = "Die Domain nutzt eine IDN-Kodierung – visuell kann sie einer anderen Seite täuschend ähneln."
            });
        }

        return BuildReport(url, uri, findings);
    }

    private static bool IsOneCharDigitVariant(string label, string brand)
    {
        if (label.Length != brand.Length) return false;
        int diff = 0;
        bool digitDiff = false;
        for (int i = 0; i < label.Length; i++)
        {
            if (label[i] == brand[i]) continue;
            diff++;
            if (diff > 1) return false;
            if (char.IsDigit(label[i])) digitDiff = true;
        }
        return diff == 1 && digitDiff;
    }

    private static UrlReport BuildReport(string input, Uri uri, List<UrlFinding> findings)
    {
        // Bewertungsregeln (transparent):
        // - Eine einzelne High-Warnung genügt für "Gefährlich" – verdächtige Struktur
        //   oder Imitation sind eindeutige Signale.
        // - Medium-Warnungen summieren sich zu "Verdächtig".
        // - Nur Low-Signale: weiterhin "Unaufällig", aber ausgewiesen.
        bool hasHigh = findings.Any(f => f.Severity == Severity.High);
        int risk = findings.Sum(f => f.Severity switch
        {
            Severity.High => 30,
            Severity.Medium => 15,
            _ => 5
        });

        UrlVerdict verdict = hasHigh ? UrlVerdict.Dangerous
            : risk > 0 ? UrlVerdict.Suspicious
            : UrlVerdict.LooksOkay;

        string summary = verdict switch
        {
            UrlVerdict.Dangerous => "Mindestens ein deutliches Warnsignal erkannt – diese Adresse mit hoher Vorsicht behandeln, am besten nicht aufrufen.",
            UrlVerdict.Suspicious => "Einige Auffälligkeiten – genau prüfen, bevor du Daten eingibst.",
            _ => "Keine der geprüften Warnsignale erkannt. Das ist keine Garantie für Sicherheit."
        };

        return new UrlReport
        {
            Input = input,
            NormalizedUrl = uri.ToString(),
            Host = uri.Host,
            Scheme = uri.Scheme,
            Verdict = verdict,
            RiskScore = risk,
            Summary = summary,
            Findings = findings
        };
    }
}

public sealed class UrlReport
{
    public required string Input { get; init; }
    public string? NormalizedUrl { get; init; }
    public string? Host { get; init; }
    public string? Scheme { get; init; }
    public UrlVerdict Verdict { get; init; }
    public int RiskScore { get; init; }
    public required string Summary { get; init; }
    public required IReadOnlyList<UrlFinding> Findings { get; init; }
}

public enum UrlVerdict { Invalid, LooksOkay, Suspicious, Dangerous }

public sealed record UrlFinding
{
    public required Severity Severity { get; init; }
    public required string Title { get; init; }
    public required string Description { get; init; }
}

public enum Severity { Low, Medium, High }
