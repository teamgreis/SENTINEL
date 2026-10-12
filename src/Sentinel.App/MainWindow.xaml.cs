using System.IO;
using Sentinel.Core;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using Sentinel.Core.Baseline;
using Sentinel.Core.Checks;
using Sentinel.Core.Integrity;
using Sentinel.Core.Reporting;
using Sentinel.Core.Scoring;
using Sentinel.Core.Settings;
using Sentinel.Core.System;
using Sentinel.Core.ThreatIntel;
using Sentinel.Core.UrlCheck;
using Sentinel.Core.Users;
using Sentinel.Platform;
using Sentinel.Platform.Checks;

namespace Sentinel.App;

public partial class MainWindow : Window
{
    private ScanReport? _report;
    private SystemBaseline? _baseline;
    private string? _selectedFilePath;
    private string? _selectedFileHash;

    static readonly string AppDataDir = Core.AppPaths.DataDir;

    private readonly HistoryStore _history;
    private readonly ConsentSettings _consent;
    private readonly AppSettings _settings;
    private readonly UserManager _users;
    private readonly ApiKeyStore _keyStore;
    private ThreatAggregator? _aggregator;

    public MainWindow()
    {
        InitializeComponent();

        Directory.CreateDirectory(AppDataDir);
        _history = new HistoryStore(Path.Combine(AppDataDir, "history.json"));
        _consent = new ConsentSettings(Path.Combine(AppDataDir, "consent.json"));
        _settings = AppSettings.Load(Path.Combine(AppDataDir, "settings.json"));
        _users = new UserManager(Path.Combine(AppDataDir, "users.json"));
        _keyStore = new ApiKeyStore(Path.Combine(AppDataDir, "apikeys.json"));

        LoadSettingsIntoUi();
        LoadDatabaseSettings();
        RenderUserInfo();
        DataPathText.Text = AppDataDir;

        var manifest = IntegrityVerifier.LoadManifest(AppContext.BaseDirectory);
        IntegrityStatusText.Text = manifest is null
            ? "Kein Manifest vorhanden – wird beim ersten Erstellen des Kontos angelegt."
            : $"Manifest vom {manifest.CreatedAt.ToLocalTime():dd.MM.yyyy HH:mm} mit {manifest.Entries.Count} Dateien.";

        RefreshStartupStatus();
    }

    // ---------- Navigation ----------

    private void Nav_Changed(object sender, RoutedEventArgs e)
    {
        if (PageOverview is null) return;

        bool overview = NavOverview.IsChecked == true;
        bool link = NavLinkShield.IsChecked == true;
        bool file = NavFileShield.IsChecked == true;
        bool baseline = NavBaseline.IsChecked == true;
        bool integrity = NavIntegrity.IsChecked == true;
        bool users = NavUsers.IsChecked == true;
        bool history = NavHistory.IsChecked == true;
        bool settings = NavSettings.IsChecked == true;

        PageOverview.Visibility = overview ? Visibility.Visible : Visibility.Collapsed;
        PageLinkShield.Visibility = link ? Visibility.Visible : Visibility.Collapsed;
        PageFileShield.Visibility = file ? Visibility.Visible : Visibility.Collapsed;
        PageBaseline.Visibility = baseline ? Visibility.Visible : Visibility.Collapsed;
        PageUsers.Visibility = users ? Visibility.Visible : Visibility.Collapsed;
        PageIntegrity.Visibility = integrity ? Visibility.Visible : Visibility.Collapsed;
        PageHistory.Visibility = history ? Visibility.Visible : Visibility.Collapsed;
        PageSettings.Visibility = settings ? Visibility.Visible : Visibility.Collapsed;
        PageAbout.Visibility = !overview && !link && !file && !baseline && !integrity && !history && !settings
            ? Visibility.Visible : Visibility.Collapsed;

        if (history) RenderHistory();
        if (baseline) RefreshBaselineStatus();
        if (users) RenderUsers();
    }

    // ---------- Prüfung ----------

    private async void RunScan_Click(object sender, RoutedEventArgs e)
    {
        RunScanButton.IsEnabled = false;
        RunScanButton.Content = "Prüfe …";
        ResultsPanel.Children.Clear();
        ResultsPanel.Children.Add(new TextBlock
        {
            Text = "Prüfungen laufen …",
            Foreground = (Brush)FindResource("TextMuted"),
            Margin = new Thickness(0, 0, 0, 10)
        });

        try
        {
            var runner = new ScanRunner(CheckRegistry.CreateDefault());
            _report = await runner.RunAsync();
            RenderResults(_report);
            try { _history.Append(_report.Score); } catch { }
            ExportButton.IsEnabled = true;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Die Prüfung konnte nicht abgeschlossen werden:\n\n{ex.Message}",
                "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            RunScanButton.IsEnabled = true;
            RunScanButton.Content = "Prüfung starten";
        }
    }

    private void RenderResults(ScanReport report)
    {
        ScoreValue.Text = report.Score.Value.ToString();
        var scoreBrush = report.Score.Grade switch
        {
            ScoreGrade.Gut => (Brush)FindResource("Green"),
            ScoreGrade.Verbesserungsbedarf => (Brush)FindResource("Amber"),
            ScoreGrade.Kritisch => (Brush)FindResource("Red"),
            _ => (Brush)FindResource("TextMuted")
        };
        ScoreValue.Foreground = scoreBrush;
        ScoreArc.Stroke = scoreBrush;

        double circumference = 2 * Math.PI * 56;
        double fraction = Math.Clamp(report.Score.Value / 100.0, 0, 1);
        ScoreArc.StrokeDashArray = new DoubleCollection { circumference, circumference };
        ScoreArc.StrokeDashOffset = circumference * (1 - fraction);

        ScoreGradeText.Text = report.Score.Grade switch
        {
            ScoreGrade.Gut => "Gut — die wichtigsten Grundlagen stehen",
            ScoreGrade.Verbesserungsbedarf => "Verbesserungsbedarf — es gibt offene Punkte",
            ScoreGrade.Kritisch => "Kritisch — wichtige Schutzmaßnahmen fehlen",
            _ => "Keine bewertbaren Ergebnisse"
        };
        ScoreSummaryText.Text =
            $"Bewertete Prüfungen: {report.Score.Graded} — " +
            $"{report.Score.Passed} bestanden, {report.Score.Warnings} mit Hinweis, " +
            $"{report.Score.Failed} nicht bestanden, {report.Score.Unknown} unklar.";
        LastRunText.Text = $"Letzte Prüfung: {report.FinishedAt.ToLocalTime():dd.MM.yyyy HH:mm} " +
                           $"(Dauer {(report.FinishedAt - report.StartedAt).TotalSeconds:F1} s)";

        // Trend aus Verlauf
        var entries = _history.Load().OrderBy(x => x.Timestamp).ToList();
        if (entries.Count >= 2)
        {
            var last = entries[^1];
            var prev = entries[^2];
            int delta = last.Score - prev.Score;
            TrendText.Text = delta == 0
                ? "Trend: unverändert zur vorherigen Prüfung."
                : $"Trend: {(delta > 0 ? "▲ +" : "▼ ")}{delta} Punkte gegenüber der vorherigen Prüfung.";
            TrendText.Foreground = delta > 0 ? (Brush)FindResource("Green")
                : delta < 0 ? (Brush)FindResource("Red")
                : (Brush)FindResource("TextMuted");
        }
        else TrendText.Text = "";

        ResultsPanel.Children.Clear();
        foreach (var group in report.Results.GroupBy(CategoryOf).OrderBy(g => CategoryOrder(g.Key)))
        {
            ResultsPanel.Children.Add(new TextBlock
            {
                Text = CategoryLabel(group.Key),
                FontSize = 12, FontWeight = FontWeights.Bold,
                Foreground = (Brush)FindResource("TextMuted"),
                Margin = new Thickness(0, 10, 0, 8)
            });

            foreach (var r in group.OrderByDescending(r => r.Weight))
                ResultsPanel.Children.Add(BuildResultCard(r));
        }
    }

    private static string CategoryOf(CheckResult r) => r.Id.Split('.')[0] switch
    {
        "system" => "system",
        "accounts" => "accounts",
        "network" => "network",
        "startup" => "startup",
        "persistence" => "persistence",
        _ => "other"
    };

    private static int CategoryOrder(string key) => key switch
    {
        "system" => 0,
        "accounts" => 1,
        "network" => 2,
        "startup" => 3,
        "persistence" => 4,
        _ => 5
    };

    private static string CategoryLabel(string key) => key switch
    {
        "system" => "SYSTEM",
        "accounts" => "KONTEN",
        "network" => "NETZWERK",
        "startup" => "STARTVERHALTEN",
        "persistence" => "PERSISTENZ & VERTEIDIGUNG",
        _ => "SONSTIGES"
    };

    private Border BuildResultCard(CheckResult r)
    {
        (string icon, Brush color) = r.Status switch
        {
            CheckStatus.Pass => ("✓", (Brush)FindResource("Green")),
            CheckStatus.Warning => ("!", (Brush)FindResource("Amber")),
            CheckStatus.Fail => ("✗", (Brush)FindResource("Red")),
            CheckStatus.Unknown => ("?", (Brush)FindResource("TextMuted")),
            _ => ("i", (Brush)FindResource("Cyan"))
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var badge = new Border
        {
            Width = 32, Height = 32, CornerRadius = new CornerRadius(16),
            Background = color, Margin = new Thickness(0, 0, 14, 0),
            VerticalAlignment = VerticalAlignment.Top
        };
        badge.Child = new TextBlock
        {
            Text = icon, Foreground = Brushes.Black, FontSize = 15, FontWeight = FontWeights.Bold,
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center
        };
        grid.Children.Add(badge);

        var stack = new StackPanel();
        Grid.SetColumn(stack, 1);

        stack.Children.Add(new TextBlock
        {
            Text = r.Title, FontSize = 15, FontWeight = FontWeights.SemiBold, Foreground = Brushes.White
        });
        stack.Children.Add(new TextBlock
        {
            Text = r.Detail, Foreground = (Brush)FindResource("Text"),
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 0)
        });

        if (_settings.ShowExplanations)
        {
            stack.Children.Add(new TextBlock
            {
                Text = r.Explanation, Foreground = (Brush)FindResource("TextMuted"),
                TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 0), FontSize = 13
            });
        }

        if (r.RecommendedActions.Count > 0)
        {
            stack.Children.Add(new TextBlock
            {
                Text = "Nächste Schritte:", Foreground = (Brush)FindResource("Cyan"),
                FontSize = 12, Margin = new Thickness(0, 6, 0, 2)
            });
            foreach (var a in r.RecommendedActions)
            {
                stack.Children.Add(new TextBlock
                {
                    Text = $"• {a}", Foreground = (Brush)FindResource("TextMuted"),
                    TextWrapping = TextWrapping.Wrap, FontSize = 12, Margin = new Thickness(6, 1, 0, 0)
                });
            }
        }

        if (_settings.ShowAdvancedDetails && (r.Limitations is { Length: > 0 } || r.Source is { Length: > 0 }))
        {
            var meta = new List<string>();
            if (r.Limitations is { Length: > 0 }) meta.Add($"Grenzen: {r.Limitations}");
            if (r.Source is { Length: > 0 }) meta.Add($"Quelle: {r.Source}");
            stack.Children.Add(new TextBlock
            {
                Text = string.Join(" | ", meta),
                Foreground = (Brush)FindResource("TextFaint"),
                TextWrapping = TextWrapping.Wrap, FontSize = 11, Margin = new Thickness(0, 4, 0, 0)
            });
        }

        grid.Children.Add(stack);

        return new Border { Style = (Style)FindResource("Card"), Child = grid };
    }

    // ---------- LinkShield ----------

    private void CheckUrl_Click(object sender, RoutedEventArgs e)
    {
        var report = new UrlAnalyzer().Analyze(UrlInput.Text);
        UrlResultCard.Visibility = Visibility.Visible;
        UrlOnlineResult.Visibility = Visibility.Collapsed;

        Brush color = report.Verdict switch
        {
            UrlVerdict.Dangerous => (Brush)FindResource("Red"),
            UrlVerdict.Suspicious => (Brush)FindResource("Amber"),
            UrlVerdict.LooksOkay => (Brush)FindResource("Green"),
            _ => (Brush)FindResource("TextMuted")
        };

        UrlVerdictHead.Foreground = color;
        UrlVerdictHead.Text = report.Verdict switch
        {
            UrlVerdict.Dangerous => "⚠ Gefährlich",
            UrlVerdict.Suspicious => "! Verdächtig",
            UrlVerdict.LooksOkay => "✓ Keine Signale erkannt",
            _ => "– Keine gültige URL"
        };

        var body = new System.Text.StringBuilder();
        body.AppendLine(report.Summary);
        if (report.Findings.Count > 0)
        {
            body.AppendLine();
            body.AppendLine("Erkannte Signale:");
            foreach (var f in report.Findings)
                body.AppendLine($"• {f.Title} — {f.Description}");
            body.AppendLine();
            body.Append("Hinweis: offline geprüft, nur dokumentierte Signale. Keine Garantie.");
        }
        UrlVerdictBody.Text = body.ToString();
    }

    private async void CheckUrlOnline_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureOnlineConsent()) return;

        var url = UrlInput.Text?.Trim();
        if (string.IsNullOrWhiteSpace(url)) return;

        UrlOnlineButton.IsEnabled = false;
        UrlOnlineResult.Visibility = Visibility.Visible;
        UrlOnlineResult.Text = "Online-Prüfung läuft (URLhaus) …";

        try
        {
            using var transport = new HttpClientTransport();
            var client = new UrlHausClient(transport);
            var result = await client.LookupUrlAsync(url);

            UrlOnlineResult.Foreground = result.IsKnownMalicious
                ? (Brush)FindResource("Red")
                : result.QuerySucceeded ? (Brush)FindResource("Green") : (Brush)FindResource("Amber");

            UrlOnlineResult.Text = result.QuerySucceeded
                ? (result.IsKnownMalicious
                    ? $"⚠ IN URLHAUS GELISTET: {result.Signature} — Diese Adresse ist als bösartig bekannt. Nicht aufrufen!"
                    : "✓ Kein Eintrag in URLhaus gefunden. (Keine Garantie für Sicherheit.)")
                : $"Online-Prüfung fehlgeschlagen: {result.Error}";
        }
        catch (Exception ex)
        {
            UrlOnlineResult.Foreground = (Brush)FindResource("Amber");
            UrlOnlineResult.Text = $"Online-Prüfung fehlgeschlagen: {ex.Message}";
        }
        finally
        {
            UrlOnlineButton.IsEnabled = true;
        }
    }

    // ---------- FileShield ----------

    private void BrowseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Datei für FileShield auswählen", CheckFileExists = true };
        if (dialog.ShowDialog() == true)
        {
            _selectedFilePath = dialog.FileName;
            _selectedFileHash = null;
            FilePathBox.Text = _selectedFilePath;
            ScanFileButton.IsEnabled = true;
            FileResultCard.Visibility = Visibility.Collapsed;
            FileOnlineResult.Visibility = Visibility.Collapsed;
        }
    }

    private void ScanFile_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedFilePath is null || !File.Exists(_selectedFilePath))
        {
            FileResultCard.Visibility = Visibility.Visible;
            FileVerdictHead.Foreground = (Brush)FindResource("Amber");
            FileVerdictHead.Text = "Datei nicht gefunden";
            FileVerdictBody.Text = "Die ausgewählte Datei existiert nicht mehr.";
            return;
        }

        try
        {
            var info = new FileInfo(_selectedFilePath);
            byte[] header = LocalFileInspector.ReadHeaderAsync(_selectedFilePath).GetAwaiter().GetResult();
            byte[] scanBuffer = new byte[Math.Min(info.Length, 2 * 1024 * 1024)];
            using (var fs = File.OpenRead(_selectedFilePath))
                fs.ReadExactly(scanBuffer);

            string? type = LocalFileInspector.DetectType(header);
            var risks = LocalFileInspector.AnalyzeRisks(scanBuffer);
            _selectedFileHash = FileHasher.ComputeSha256(scanBuffer);

            FileResultCard.Visibility = Visibility.Visible;
            FileOnlineResult.Visibility = Visibility.Collapsed;
            FileOnlineButton.IsEnabled = true;

            bool hasRisk = risks.Count > 0;
            FileVerdictHead.Foreground = hasRisk ? (Brush)FindResource("Amber") : (Brush)FindResource("Cyan");
            FileVerdictHead.Text = hasRisk ? "Auffälligkeiten erkannt" : "Keine lokalen Auffälligkeiten";

            var body = new System.Text.StringBuilder();
            body.AppendLine($"Datei: {Path.GetFileName(_selectedFilePath)}");
            body.AppendLine($"Größe: {info.Length / 1024.0:F1} KB");
            body.AppendLine($"Typ (Magic Bytes): {type ?? "unbekannt"}");
            body.AppendLine($"SHA-256: {_selectedFileHash}");
            if (risks.Count > 0)
            {
                body.AppendLine();
                body.AppendLine("Hinweise:");
                foreach (var r in risks)
                    body.AppendLine($"• {r}");
            }
            else
            {
                body.AppendLine();
                body.Append("Lokal keine der geprüften Auffälligkeiten gefunden. Das ist keine Freigabe – FileShield führt die Datei nicht aus.");
            }
            FileVerdictBody.Text = body.ToString();
        }
        catch (Exception ex)
        {
            FileResultCard.Visibility = Visibility.Visible;
            FileVerdictHead.Foreground = (Brush)FindResource("Red");
            FileVerdictHead.Text = "Prüfung fehlgeschlagen";
            FileVerdictBody.Text = ex.Message;
        }
    }

    private async void ScanFileOnline_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureOnlineConsent()) return;
        if (_selectedFileHash is null)
        {
            FileOnlineResult.Visibility = Visibility.Visible;
            FileOnlineResult.Text = "Erst lokal prüfen, um den Hash zu berechnen.";
            return;
        }

        FileOnlineButton.IsEnabled = false;
        FileOnlineResult.Visibility = Visibility.Visible;
        FileOnlineResult.Text = "Online-Prüfung läuft (MalwareBazaar) — nur der Hash wird übertragen …";

        try
        {
            using var transport = new HttpClientTransport();
            var client = new MalwareBazaarClient(transport);
            var result = await client.LookupHashAsync(_selectedFileHash);

            FileOnlineResult.Foreground = result.IsKnownMalicious
                ? (Brush)FindResource("Red")
                : result.QuerySucceeded ? (Brush)FindResource("Green") : (Brush)FindResource("Amber");

            if (result.IsKnownMalicious)
            {
                var sb = new System.Text.StringBuilder();
                sb.AppendLine("⚠ BEKANNTE SCHADSOFTWARE — Datei nicht öffnen!");
                if (result.Signature is { Length: > 0 }) sb.AppendLine($"Signatur: {result.Signature}");
                if (result.FileType is { Length: > 0 }) sb.AppendLine($"Typ: {result.FileType}");
                if (result.FirstSeen is { Length: > 0 }) sb.AppendLine($"Erstmals gesehen: {result.FirstSeen}");
                sb.Append("Quelle: MalwareBazaar (abuse.ch). Datei löschen oder mit dem Virenscanner prüfen.");
                FileOnlineResult.Text = sb.ToString();
            }
            else if (result.QuerySucceeded)
            {
                FileOnlineResult.Text = "✓ Kein Eintrag in MalwareBazaar gefunden. Das ist KEINE Garantie, dass die Datei harmlos ist – unbekannte Schadsoftware wird darüber nicht erkannt.";
            }
            else
            {
                FileOnlineResult.Text = $"Online-Prüfung fehlgeschlagen: {result.Error}";
            }
        }
        catch (Exception ex)
        {
            FileOnlineResult.Foreground = (Brush)FindResource("Amber");
            FileOnlineResult.Text = $"Online-Prüfung fehlgeschlagen: {ex.Message}";
        }
        finally
        {
            FileOnlineButton.IsEnabled = true;
        }
    }

    // ---------- Baseline ----------

    private void RefreshBaselineStatus()
    {
        var path = Path.Combine(AppDataDir, "baseline.json");
        if (File.Exists(path))
        {
            var b = SystemBaseline.FromJson(File.ReadAllText(path));
            if (b is not null)
            {
                BaselineStatusText.Text =
                    $"Normalzustand gelernt am {b.CapturedAt.ToLocalTime():dd.MM.yyyy HH:mm} " +
                    $"({b.LocalUsers.Count} Benutzer, {b.Services.Count} Dienste, " +
                    $"{b.AutostartEntries.Count} Autostarts, {b.ScheduledTasks.Count} Aufgaben).";
                BaselineCheckButton.IsEnabled = true;
                return;
            }
        }

        BaselineStatusText.Text = "Noch kein Normalzustand gelernt. Lerne ihn, solange dein System sauber ist.";
        BaselineCheckButton.IsEnabled = false;
    }

    private async void BaselineLearn_Click(object sender, RoutedEventArgs e)
    {
        BaselineLearnButton.IsEnabled = false;
        BaselineLearnButton.Content = "Lerne System …";

        try
        {
            _baseline = await BaselineCollector.CollectAsync();
            var path = Path.Combine(AppDataDir, "baseline.json");
            File.WriteAllText(path, _baseline.ToJson());
            RefreshBaselineStatus();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Lernen fehlgeschlagen:\n{ex.Message}", "SENTINEL",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            BaselineLearnButton.IsEnabled = true;
            BaselineLearnButton.Content = "Normalzustand lernen";
        }
    }

    private async void BaselineCheck_Click(object sender, RoutedEventArgs e)
    {
        var path = Path.Combine(AppDataDir, "baseline.json");
        if (!File.Exists(path)) return;

        var baseline = SystemBaseline.FromJson(File.ReadAllText(path));
        if (baseline is null) return;

        BaselineCheckButton.IsEnabled = false;
        BaselineCheckButton.Content = "Vergleiche …";

        try
        {
            var current = await BaselineCollector.CollectAsync();
            var comparison = BaselineComparer.Compare(baseline, current);
            RenderBaselineComparison(comparison);

            // Optional: Baseline automatisch aktualisieren
            if (_settings.AutoUpdateBaseline && !comparison.HasDeviations)
            {
                _baseline = current;
                File.WriteAllText(path, current.ToJson());
                RefreshBaselineStatus();
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Vergleich fehlgeschlagen:\n{ex.Message}", "SENTINEL",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            BaselineCheckButton.IsEnabled = true;
            BaselineCheckButton.Content = "Jetzt vergleichen";
        }
    }

    private void RenderBaselineComparison(BaselineComparison comparison)
    {
        BaselineResultCard.Visibility = Visibility.Visible;
        BaselineResultPanel.Children.Clear();

        if (!comparison.HasDeviations)
        {
            BaselineResultPanel.Children.Add(new TextBlock
            {
                Text = "✓ Keine Abweichungen vom gelernten Normalzustand.",
                Foreground = (Brush)FindResource("Green"),
                FontSize = 15, FontWeight = FontWeights.SemiBold
            });
            return;
        }

        int threshold = _settings.BaselineAlertThreshold;
        var notable = comparison.Notable.Where(d => d.Suspicion >= threshold).ToList();
        var minor = comparison.Deviations.Where(d => d.Suspicion < threshold).ToList();

        BaselineResultPanel.Children.Add(new TextBlock
        {
            Text = notable.Count > 0
                ? $"⚠ {notable.Count} auffällige Abweichung(en) erkannt!"
                : $"{comparison.Deviations.Count} Änderung(en), keine davon über der Warnschwelle.",
            Foreground = notable.Count > 0 ? (Brush)FindResource("Amber") : (Brush)FindResource("Cyan"),
            FontSize = 15, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 10)
        });

        if (notable.Count > 0)
        {
            BaselineResultPanel.Children.Add(new TextBlock
            {
                Text = "Auffällig:",
                Foreground = (Brush)FindResource("Red"), FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 4, 0, 4)
            });
            foreach (var d in notable)
            {
                BaselineResultPanel.Children.Add(new TextBlock
                {
                    Text = d.Detail is { Length: > 0 } ? $"• {d.Describe()} — {d.Detail}" : $"• {d.Describe()}",
                    Foreground = (Brush)FindResource("Text"), TextWrapping = TextWrapping.Wrap,
                    FontSize = 13, Margin = new Thickness(8, 2, 0, 2)
                });
            }
        }

        if (minor.Count > 0 && _settings.ShowAdvancedDetails)
        {
            BaselineResultPanel.Children.Add(new TextBlock
            {
                Text = "Weitere Änderungen (unter der Warnschwelle):",
                Foreground = (Brush)FindResource("TextMuted"), FontSize = 12,
                Margin = new Thickness(0, 10, 0, 4)
            });
            foreach (var d in minor)
            {
                BaselineResultPanel.Children.Add(new TextBlock
                {
                    Text = $"• {d.Describe()}",
                    Foreground = (Brush)FindResource("TextFaint"), TextWrapping = TextWrapping.Wrap,
                    FontSize = 12, Margin = new Thickness(8, 1, 0, 1)
                });
            }
        }
    }

    // ---------- Integrität ----------

    private void RunIntegrity_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string appDir = AppContext.BaseDirectory;
            var manifest = IntegrityVerifier.LoadManifest(appDir);

            IntegrityResultCard.Visibility = Visibility.Visible;
            IntegrityResultPanel.Children.Clear();

            if (manifest is null)
            {
                IntegrityResultPanel.Children.Add(new TextBlock
                {
                    Text = "Kein Manifest vorhanden. Es wird jetzt erzeugt.",
                    Foreground = (Brush)FindResource("Amber")
                });
                var ownFiles = Directory.EnumerateFiles(appDir, "Sentinel*.dll")
                    .Concat(Directory.EnumerateFiles(appDir, "Sentinel.exe"))
                    .Select(Path.GetFileName).Where(n => n is not null).Cast<string>().ToList();
                var created = IntegrityVerifier.CreateManifest(appDir, ownFiles);
                IntegrityVerifier.SaveManifest(appDir, created);
                RefreshIntegrityStatus();
                return;
            }

            var report = IntegrityVerifier.Verify(appDir, manifest);

            IntegrityResultPanel.Children.Add(new TextBlock
            {
                Text = report.IsIntact
                    ? $"✓ {report.Summary}"
                    : $"⚠ {report.Summary}",
                Foreground = report.IsIntact ? (Brush)FindResource("Green") : (Brush)FindResource("Red"),
                FontSize = 15, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 10)
            });

            foreach (var problem in report.Problems)
            {
                IntegrityResultPanel.Children.Add(new TextBlock
                {
                    Text = $"• {problem.FileName}: {problem.Status}",
                    Foreground = (Brush)FindResource("Text"), FontSize = 13,
                    TextWrapping = TextWrapping.Wrap, Margin = new Thickness(8, 2, 0, 2)
                });
            }

            if (!report.IsIntact && _settings.BlockIfManipulated)
            {
                IntegrityResultPanel.Children.Add(new TextBlock
                {
                    Text = "Hinweis: Bei Manipulation verweigert SENTINEL beim nächsten Start den Start (Einstellung „Bei Manipulation Start verweigern\").",
                    Foreground = (Brush)FindResource("Amber"), FontSize = 12,
                    TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 0)
                });
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Integritätsprüfung fehlgeschlagen:\n{ex.Message}", "SENTINEL",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void RefreshIntegrityStatus()
    {
        var manifest = IntegrityVerifier.LoadManifest(AppContext.BaseDirectory);
        IntegrityStatusText.Text = manifest is null
            ? "Kein Manifest vorhanden."
            : $"Manifest vom {manifest.CreatedAt.ToLocalTime():dd.MM.yyyy HH:mm} mit {manifest.Entries.Count} Dateien.";
    }

    // ---------- Verlauf ----------

    private void RenderHistory()
    {
        HistoryPanel.Children.Clear();
        var entries = _history.Load();

        if (entries.Count == 0)
        {
            HistoryPanel.Children.Add(new TextBlock
            {
                Text = "Noch keine gespeicherten Prüfungen. Führe eine Prüfung über die Übersicht aus.",
                Style = (Style)FindResource("Muted")
            });
            return;
        }

        foreach (var entry in entries.OrderByDescending(x => x.Timestamp))
        {
            var grid = new Grid { Margin = new Thickness(0, 4, 0, 4) };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(140) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            grid.Children.Add(new TextBlock
            {
                Text = entry.Timestamp.ToLocalTime().ToString("dd.MM. HH:mm"),
                Foreground = (Brush)FindResource("TextMuted"), FontSize = 13,
                VerticalAlignment = VerticalAlignment.Center
            });

            var bar = new Border
            {
                Height = 10, CornerRadius = new CornerRadius(5),
                Background = new SolidColorBrush(Color.FromRgb(0x2A, 0x27, 0x40)),
                Margin = new Thickness(10, 0, 10, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            var fill = new Border
            {
                Height = 10, CornerRadius = new CornerRadius(5),
                HorizontalAlignment = HorizontalAlignment.Left, MinWidth = 4,
                Background = entry.Score >= 80 ? (Brush)FindResource("Green")
                    : entry.Score >= 50 ? (Brush)FindResource("Amber")
                    : (Brush)FindResource("Red")
            };
            var holder = new Grid();
            holder.Children.Add(bar);
            holder.Children.Add(fill);
            Grid.SetColumn(holder, 1);
            grid.Children.Add(holder);

            grid.Children.Add(new TextBlock
            {
                Text = $"{entry.Score} / 100",
                Foreground = Brushes.White, FontSize = 13, FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });
            Grid.SetColumn((UIElement)grid.Children[^1], 2);

            HistoryPanel.Children.Add(grid);
        }

        HistoryPanel.Children.Add(new TextBlock
        {
            Text = $"Aufbewahrung: {_settings.HistoryRetentionDays} Tage · Gespeichert in %LOCALAPPDATA%\\SENTINEL\\history.json",
            Style = (Style)FindResource("Muted"), FontSize = 11, Margin = new Thickness(0, 12, 0, 0)
        });
    }

    private void ClearHistory_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "Wirklich den gesamten Verlauf löschen? Das kann nicht rückgängig gemacht werden.",
            "SENTINEL", MessageBoxButton.YesNo, MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes) return;

        try { _history.Clear(); } catch (Exception ex)
        {
            MessageBox.Show($"Löschen fehlgeschlagen:\n{ex.Message}", "SENTINEL",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        RenderHistory();
    }

    // ---------- Einstellungen ----------

    private void LoadSettingsIntoUi()
    {
        // Design-Auswahl füllen (nur beim ersten Aufruf)
        if (SetThemeCombo.Items.Count == 0)
        {
            foreach (var mode in ThemeManager.All)
                SetThemeCombo.Items.Add(ThemeManager.DisplayName(mode));
        }
        SetThemeCombo.SelectedIndex = Array.IndexOf(ThemeManager.All.ToArray(), ThemeManager.Parse(_settings.Theme.ToString()));

        SetShowExplanations.IsChecked = _settings.ShowExplanations;
        SetShowAdvancedDetails.IsChecked = _settings.ShowAdvancedDetails;
        SetCompactMode.IsChecked = _settings.CompactMode;
        SetAnimationsEnabled.IsChecked = _settings.AnimationsEnabled;
        SetColorBlindMode.IsChecked = _settings.ColorBlindMode;

        SetCheckOnStartup.IsChecked = _settings.CheckOnStartup;
        SetMinimizeToTray.IsChecked = _settings.MinimizeToTray;
        SetRunAtWindowsStartup.IsChecked = _settings.RunAtWindowsStartup;
        SetStartupCheckQuietMode.IsChecked = _settings.StartupCheckQuietMode;
        SetAutoExportReport.IsChecked = _settings.AutoExportReport;

        SetIncludeInfoInScore.IsChecked = _settings.IncludeInfoChecksInScore;
        SetTreatWarningsAsFailures.IsChecked = _settings.TreatWarningsAsFailures;
        SetMinScore.SelectedIndex = _settings.MinimumScoreForGoodGrade switch
        {
            70 => 0, 75 => 1, 80 => 2, 85 => 3, 90 => 4, _ => 2
        };

        SetOnlineChecks.IsChecked = _settings.OnlineChecksEnabled;
        SetConfirmBeforeOnline.IsChecked = _settings.ConfirmBeforeOnlineCheck;
        SetTelemetry.IsChecked = false;

        SetBaselineEnabled.IsChecked = _settings.BaselineEnabled;
        SetAutoUpdateBaseline.IsChecked = _settings.AutoUpdateBaseline;
        SetBaselineThreshold.Value = _settings.BaselineAlertThreshold;

        SetRequirePassword.IsChecked = _settings.RequirePasswordOnStart;
        SetLockAfterInactivity.IsChecked = _settings.LockAfterInactivity;
        SetLockAfterMinutes.Value = _settings.LockAfterMinutes;
        SetIntegrityCheckOnStart.IsChecked = _settings.IntegrityCheckOnStart;
        SetBlockIfManipulated.IsChecked = _settings.BlockIfManipulated;

        SetHistoryRetention.Value = _settings.HistoryRetentionDays;
        SetIncludeHistoryInExport.IsChecked = _settings.IncludeHistoryInExport;
        SetIncludeHashInExport.IsChecked = _settings.IncludeHashInExport;

        SetAutoCheckUpdates.IsChecked = _settings.AutoCheckUpdates;
        SetNotifyOnlyCritical.IsChecked = _settings.NotifyOnlyCriticalUpdates;

        UpdateSliderLabels();
        UpdateConsentState();
    }

    private void UpdateSliderLabels()
    {
        BaselineThresholdValue.Text = ((int)SetBaselineThreshold.Value).ToString();
        LockAfterMinutesValue.Text = ((int)SetLockAfterMinutes.Value).ToString();
        HistoryRetentionValue.Text = ((int)SetHistoryRetention.Value).ToString();
    }

    private void SettingChanged(object sender, RoutedEventArgs e)
    {
        if (_settings is null) return;

        _settings.ShowExplanations = SetShowExplanations.IsChecked == true;
        _settings.ShowAdvancedDetails = SetShowAdvancedDetails.IsChecked == true;
        _settings.CompactMode = SetCompactMode.IsChecked == true;
        _settings.AnimationsEnabled = SetAnimationsEnabled.IsChecked == true;
        _settings.ColorBlindMode = SetColorBlindMode.IsChecked == true;

        _settings.CheckOnStartup = SetCheckOnStartup.IsChecked == true;
        _settings.MinimizeToTray = SetMinimizeToTray.IsChecked == true;
        _settings.RunAtWindowsStartup = SetRunAtWindowsStartup.IsChecked == true;
        _settings.StartupCheckQuietMode = SetStartupCheckQuietMode.IsChecked == true;
        _settings.AutoExportReport = SetAutoExportReport.IsChecked == true;

        _settings.IncludeInfoChecksInScore = SetIncludeInfoInScore.IsChecked == true;
        _settings.TreatWarningsAsFailures = SetTreatWarningsAsFailures.IsChecked == true;
        if (SetMinScore.SelectedItem is ComboBoxItem item && int.TryParse(item.Content.ToString(), out var min))
            _settings.MinimumScoreForGoodGrade = min;

        _settings.ConfirmBeforeOnlineCheck = SetConfirmBeforeOnline.IsChecked == true;

        _settings.BaselineEnabled = SetBaselineEnabled.IsChecked == true;
        _settings.AutoUpdateBaseline = SetAutoUpdateBaseline.IsChecked == true;
        _settings.BaselineAlertThreshold = (int)SetBaselineThreshold.Value;

        _settings.RequirePasswordOnStart = SetRequirePassword.IsChecked == true;
        _settings.LockAfterInactivity = SetLockAfterInactivity.IsChecked == true;
        _settings.LockAfterMinutes = (int)SetLockAfterMinutes.Value;
        _settings.IntegrityCheckOnStart = SetIntegrityCheckOnStart.IsChecked == true;
        _settings.BlockIfManipulated = SetBlockIfManipulated.IsChecked == true;

        _settings.HistoryRetentionDays = (int)SetHistoryRetention.Value;
        _settings.IncludeHistoryInExport = SetIncludeHistoryInExport.IsChecked == true;
        _settings.IncludeHashInExport = SetIncludeHashInExport.IsChecked == true;

        _settings.AutoCheckUpdates = SetAutoCheckUpdates.IsChecked == true;
        _settings.NotifyOnlyCriticalUpdates = SetNotifyOnlyCritical.IsChecked == true;

        UpdateSliderLabels();
        _settings.Save(Path.Combine(AppDataDir, "settings.json"));
    }

    /// <summary>Design-Auswahl: Dictionary tauschen und speichern.</summary>
    private void ThemeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_settings is null) return;

        int idx = SetThemeCombo.SelectedIndex;
        if (idx < 0 || idx >= ThemeManager.All.Count) return;

        var mode = ThemeManager.All[idx];
        bool applied = ThemeManager.Apply(mode);

        if (applied)
        {
            _settings.Theme = mode;
            _settings.Save(Path.Combine(AppDataDir, "settings.json"));
            ThemeHint.Text = Core.Settings.ThemeNames.Hint(mode);
        }
        else
        {
            ThemeHint.Text = "Design konnte nicht geladen werden – vorheriges Design bleibt aktiv.";
        }
    }

    /// <summary>Info-Button: Lizenz, Konzept, Beschreibung, Versionsinfos.</summary>
    private void InfoButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new InfoDialog { Owner = this };
        dialog.ShowDialog();
    }

    /// <summary>Handbuch-Button: Schritt-für-Schritt im Programm.</summary>
    private void ManualButton_Click(object sender, RoutedEventArgs e)
    {
        var manual = new ManualWindow { Owner = this };
        manual.ShowDialog();
    }

    private void OnlineConsent_Changed(object sender, RoutedEventArgs e)
    {
        bool allowed = SetOnlineChecks.IsChecked == true;
        _consent.SetOnlineAllowed(allowed);
        _settings.OnlineChecksEnabled = allowed;
        _settings.Save(Path.Combine(AppDataDir, "settings.json"));
        UpdateConsentState();
    }

    private void UpdateConsentState()
    {
        bool allowed = _consent.OnlineAllowed;
        ConsentStateText.Text = allowed
            ? "Aktiv: Online-Prüfungen erlaubt. Übertragen wird nur die geprüfte Adresse bzw. der SHA-256-Hash."
            : "Inaktiv: Es wird nichts nach außen gesendet. Alle Prüfungen laufen lokal.";
    }

    private void ResetSettings_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "Alle Einstellungen auf Standard zurücksetzen?", "SENTINEL",
            MessageBoxButton.YesNo, MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes) return;

        _settings.Reset();
        _settings.Save(Path.Combine(AppDataDir, "settings.json"));
        LoadSettingsIntoUi();
    }

    private void ChangePassword_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ChangePasswordDialog { Owner = this };
        if (dialog.ShowDialog() != true) return;

        // Explizit für den angemeldeten Nutzer – kein stiller Fallback
        var current = GetCurrentUser();
        if (current is null)
        {
            MessageBox.Show("Kein Nutzer angemeldet.", "SENTINEL",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (_users.ChangePassword(current.Id, dialog.CurrentPassword, dialog.NewPassword))
            MessageBox.Show("Passwort geändert.", "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Information);
        else
            MessageBox.Show("Das aktuelle Passwort ist falsch.", "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private bool EnsureOnlineConsent()
    {
        if (_consent.OnlineAllowed) return true;

        if (_settings.ConfirmBeforeOnlineCheck)
        {
            var result = MessageBox.Show(
                "Online-Prüfungen sind noch nicht erlaubt.\n\n" +
                "Dabei wird ausschließlich die geprüfte Adresse bzw. der SHA-256-Hash der Datei " +
                "an die öffentlichen Datenbanken URLhaus und MalwareBazaar (abuse.ch) übertragen – " +
                "keine weiteren Daten, kein Dateiinhalt.\n\n" +
                "Jetzt einmalig erlauben? (Änderbar in den Einstellungen)",
                "SENTINEL — Online-Prüfung", MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result != MessageBoxResult.Yes) return false;
        }

        _consent.SetOnlineAllowed(true);
        _settings.OnlineChecksEnabled = true;
        _settings.Save(Path.Combine(AppDataDir, "settings.json"));
        SetOnlineChecks.IsChecked = true;
        UpdateConsentState();
        return true;
    }

    // ---------- Windows-Autostart ----------

    private void InstallStartup_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string exePath = Environment.ProcessPath ?? "";
            if (string.IsNullOrEmpty(exePath))
            {
                MessageBox.Show("Der Pfad zur ausführbaren Datei konnte nicht ermittelt werden.",
                    "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string script =
                "$action = New-ScheduledTaskAction -Execute '" + exePath + "' -Argument '--startup-check'; " +
                "$trigger = New-ScheduledTaskTrigger -AtLogOn; " +
                "$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5); " +
                "Register-ScheduledTask -TaskName 'SENTINEL StartupCheck' -Action $action -Trigger $trigger -Settings $settings -Description 'SENTINEL Sicherheitsprüfung bei der Anmeldung' -Force";

            var (output, error) = RunPowerShell(script);

            if (error is { Length: > 0 })
            {
                MessageBox.Show(
                    "Einrichtung fehlgeschlagen. Das passiert ohne Administrator-Rechte.\n\n" +
                    "Lösung: PowerShell als Administrator öffnen und diesen Befehl ausführen:\n\n" + script,
                    "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _settings.StartupCheckOnWindowsBoot = true;
            _settings.Save(Path.Combine(AppDataDir, "settings.json"));
            RefreshStartupStatus();
            MessageBox.Show("Startprüfung eingerichtet. SENTINEL prüft ab jetzt bei jeder Windows-Anmeldung.",
                "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Fehler: {ex.Message}", "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void RemoveStartup_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var (_, error) = RunPowerShell("Unregister-ScheduledTask -TaskName 'SENTINEL StartupCheck' -Confirm:$false");

            _settings.StartupCheckOnWindowsBoot = false;
            _settings.Save(Path.Combine(AppDataDir, "settings.json"));
            RefreshStartupStatus();

            if (error is { Length: > 0 })
                MessageBox.Show("Task konnte nicht entfernt werden (evtl. nicht vorhanden oder Rechte fehlen).",
                    "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Fehler: {ex.Message}", "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void RefreshStartupStatus()
    {
        try
        {
            var (output, _) = RunPowerShell(
                "if (Get-ScheduledTask -TaskName 'SENTINEL StartupCheck' -ErrorAction SilentlyContinue) { 'vorhanden' } else { 'nicht vorhanden' }");
            StartupTaskStatus.Text = output.Trim() == "vorhanden"
                ? "Status: eingerichtet – läuft bei jeder Windows-Anmeldung."
                : "Status: nicht eingerichtet.";
        }
        catch
        {
            StartupTaskStatus.Text = "Status: unbekannt.";
        }
    }

    private static (string Output, string Error) RunPowerShell(string script)
    {
        // Sicherheits-Härtung: Skript wird NICHT in die Kommandozeile konkateniert
        // (dort könnten Anführungszeichen im Pfad injizieren), sondern über
        // stdin mit -Command - an der Shell kommt nur eine fixe Argumentkette an.
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = System.Diagnostics.Process.Start(psi)!;
        proc.StandardInput.Write(script);
        proc.StandardInput.Close();
        string output = proc.StandardOutput.ReadToEnd();
        string error = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        return (output.Trim(), error.Trim());
    }

    // ---------- Bedrohungs-Datenbanken ----------

    private void LoadDatabaseSettings()
    {
        SetThreatFoxEnabled.IsChecked = _keyStore.IsEnabled("threatfox");
        SetVirusTotalEnabled.IsChecked = _keyStore.IsEnabled("virustotal");
        SetSafeBrowsingEnabled.IsChecked = _keyStore.IsEnabled("safebrowsing");
        SetOtxEnabled.IsChecked = _keyStore.IsEnabled("otx");

        VirusTotalKeyBox.Text = _keyStore.GetKey("virustotal") ?? "";
        SafeBrowsingKeyBox.Text = _keyStore.GetKey("safebrowsing") ?? "";
        OtxKeyBox.Text = _keyStore.GetKey("otx") ?? "";

        UpdateDatabaseStatus();
    }

    private void DatabaseToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (SetThreatFoxEnabled is null) return;

        _keyStore.SetEnabled("threatfox", SetThreatFoxEnabled.IsChecked == true);
        _keyStore.SetEnabled("virustotal", SetVirusTotalEnabled.IsChecked == true);
        _keyStore.SetEnabled("safebrowsing", SetSafeBrowsingEnabled.IsChecked == true);
        _keyStore.SetEnabled("otx", SetOtxEnabled.IsChecked == true);

        UpdateDatabaseStatus();
    }

    private void ApiKeyBox_LostFocus(object sender, RoutedEventArgs e)
    {
        if (sender is not TextBox box || box.Tag is not string providerId) return;

        string value = box.Text?.Trim() ?? "";
        _keyStore.SetKey(providerId, value.Length > 0 ? value : null);

        // Anzeige leeren (Key nicht im Klartext stehen lassen)
        if (value.Length > 0)
        {
            box.Text = value.Length > 8
                ? value[..4] + "…" + value[^4..]
                : "••••";
        }

        UpdateDatabaseStatus();
    }

    private void UpdateDatabaseStatus()
    {
        int active = 0, withKey = 0, needingKey = 0;

        foreach (var (id, needsKey) in new[]
        {
            ("threatfox", false), ("virustotal", true), ("safebrowsing", true), ("otx", true)
        })
        {
            bool enabled = _keyStore.IsEnabled(id);
            if (enabled) active++;

            bool hasKey = !string.IsNullOrWhiteSpace(_keyStore.GetKey(id));
            if (enabled && needsKey)
            {
                if (hasKey) withKey++;
                else needingKey++;
            }
            else if (enabled && hasKey) withKey++;
        }

        DatabaseStatusText.Text = active == 0
            ? "Keine Datenbank aktiv. Aktiviere mindestens ThreatFox (kein Key nötig)."
            : needingKey > 0
                ? $"{active} aktiv, davon {needingKey} ohne API-Key (bleiben bei Abfragen inaktiv). {withKey} einsatzbereit."
                : $"{active} Datenbanken aktiv und einsatzbereit.";
    }

    private ThreatAggregator GetOrCreateAggregator()
    {
        _aggregator ??= ThreatIntelFactory.Create(new HttpClientTransport(), _keyStore,
            new MemoryResultCache(), new PerProviderRateLimiter());
        return _aggregator;
    }

    private async void CheckAllDatabases_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureOnlineConsent()) return;

        var url = UrlInput.Text?.Trim();
        if (string.IsNullOrWhiteSpace(url)) return;

        UrlAllDatabasesButton.IsEnabled = false;
        UrlAllDatabasesButton.Content = "Frage ab …";
        AggregatedCard.Visibility = Visibility.Visible;
        AggregatedHead.Text = "Abfrage läuft …";
        AggregatedHead.Foreground = (Brush)FindResource("TextMuted");
        AggregatedSummary.Text = "";
        AggregatedList.ItemsSource = null;

        try
        {
            var query = new ThreatQuery(ThreatKind.Url, url);
            var aggregator = GetOrCreateAggregator();

            var verdict = await aggregator.CheckAsync(
                query,
                providerId => _keyStore.GetKey(providerId),
                providerId => _keyStore.IsEnabled(providerId));

            var headBrush = verdict.Level switch
            {
                VerdictLevel.Dangerous => (Brush)FindResource("Red"),
                VerdictLevel.Suspicious => (Brush)FindResource("Amber"),
                VerdictLevel.Clean => (Brush)FindResource("Green"),
                _ => (Brush)FindResource("TextMuted")
            };

            AggregatedHead.Foreground = headBrush;
            AggregatedHead.Text = verdict.Level switch
            {
                VerdictLevel.Dangerous => "⚠ In mehreren Datenbanken gelistet",
                VerdictLevel.Suspicious => "! In einer Datenbank gelistet",
                VerdictLevel.Clean => "✓ Keine Datenbank kennt diese Adresse",
                _ => "Abfrage nicht möglich"
            };
            AggregatedSummary.Text = verdict.Summary;

            var items = new List<AggregatedItem>();
            foreach (var o in verdict.Outcomes)
            {
                string icon, detail;
                if (!o.QuerySucceeded)
                {
                    icon = "✗";
                    detail = $"Fehlgeschlagen: {o.Error}";
                }
                else if (o.IsThreat)
                {
                    icon = "⚠";
                    detail = $"{o.Category ?? "gelistet"} — {o.Details}";
                }
                else
                {
                    icon = "✓";
                    detail = $"Kein Treffer ({o.Details})";
                }

                if (o.Latency > TimeSpan.Zero)
                    detail += $" · {o.Latency.TotalMilliseconds:F0} ms";

                items.Add(new AggregatedItem
                {
                    Icon = icon,
                    Provider = o.ProviderName,
                    Detail = detail,
                    IsThreat = o.IsThreat
                });
            }

            AggregatedList.ItemsSource = items;
        }
        catch (Exception ex)
        {
            AggregatedHead.Foreground = (Brush)FindResource("Amber");
            AggregatedHead.Text = "Abfrage fehlgeschlagen";
            AggregatedSummary.Text = ex.Message;
        }
        finally
        {
            UrlAllDatabasesButton.IsEnabled = true;
            UrlAllDatabasesButton.Content = "Alle Datenbanken abfragen";
        }
    }

    private sealed class AggregatedItem
    {
        public string Icon { get; set; } = "";
        public string Provider { get; set; } = "";
        public string Detail { get; set; } = "";
        public bool IsThreat { get; set; }
    }

    // ---------- Nutzer & Sperre ----------

    private void RenderUserInfo()
    {
        var user = _users.Users.FirstOrDefault();
        if (user is null) return;

        UserNameText.Text = user.DisplayName;
        UserMetaText.Text = $"Konto seit {user.CreatedAt.ToLocalTime():dd.MM.yyyy}" +
                            (user.LastLoginAt is not null ? $" · letzter Login {user.LastLoginAt.Value.ToLocalTime():dd.MM. HH:mm}" : "");
    }

    // ---------- Nutzerverwaltung ----------

    private sealed class UserRow
    {
        public string Id { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string RoleText { get; set; } = "";
        public string MetaText { get; set; } = "";
    }

    private void RenderUsers()
    {
        var current = GetCurrentUser();

        if (current is not null)
        {
            CurrentUserText.Text = current.DisplayName;
            CurrentUserRole.Text = current.IsAdmin
                ? "Administrator — darf Nutzer, Rollen und Einstellungen verwalten."
                : "Nutzer — darf prüfen und berichten.";
        }

        bool isAdmin = current?.IsAdmin == true;
        AddUserButton.IsEnabled = isAdmin;
        ImportWindowsButton.IsEnabled = isAdmin;

        UserList.ItemsSource = _users.Users.Select(u => new UserRow
        {
            Id = u.Id,
            DisplayName = u.DisplayName,
            RoleText = u.IsAdmin ? "Administrator" : "Nutzer",
            MetaText = $"Konto seit {u.CreatedAt.ToLocalTime():dd.MM.yyyy}" +
                       (u.LastLoginAt is not null ? $" · Login {u.LastLoginAt.Value.ToLocalTime():dd.MM. HH:mm}" : "")
        }).ToList();

        UsersHint.Text = isAdmin
            ? "Der letzte Administrator kann nicht entfernt oder herabgestuft werden – so bleibt das System nie verwaiset."
            : "Nur Administratoren können Nutzer verwalten.";
    }

    private void AddUser_Click(object sender, RoutedEventArgs e)
    {
        if (GetCurrentUser()?.IsAdmin != true)
        {
            MessageBox.Show("Nur Administratoren dürfen Nutzer hinzufügen.",
                "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var dialog = new AddUserDialog();
        if (dialog.ShowDialog() != true) return;

        try
        {
            _users.AddUser(dialog.UserName, dialog.UserPassword, dialog.Role);
            RenderUsers();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Nutzer konnte nicht angelegt werden: {ex.Message}",
                "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ChangeUserRole_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button button || button.Tag is not string userId) return;

        if (GetCurrentUser()?.IsAdmin != true)
        {
            MessageBox.Show("Nur Administratoren dürfen Rollen ändern.",
                "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var target = _users.Users.FirstOrDefault(u => u.Id == userId);
        if (target is null) return;

        var newRole = target.IsAdmin ? UserRole.User : UserRole.Admin;

        try
        {
            _users.ChangeRole(userId, newRole);
            RenderUsers();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void AdminResetPassword_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button button || button.Tag is not string userId) return;

        if (GetCurrentUser()?.IsAdmin != true)
        {
            MessageBox.Show("Nur Administratoren dürfen Passwörter zurücksetzen.",
                "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var target = _users.Users.FirstOrDefault(u => u.Id == userId);
        if (target is null) return;

        var dialog = new AdminResetPasswordDialog(target.DisplayName);
        if (dialog.ShowDialog() == true)
        {
            _users.ResetPassword(userId, dialog.NewPassword);
            MessageBox.Show($"Passwort für {target.DisplayName} zurückgesetzt.",
                "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void RemoveUser_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button button || button.Tag is not string userId) return;

        if (GetCurrentUser()?.IsAdmin != true)
        {
            MessageBox.Show("Nur Administratoren dürfen Nutzer entfernen.",
                "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var target = _users.Users.FirstOrDefault(u => u.Id == userId);
        if (target is null) return;

        var result = MessageBox.Show(
            $"Nutzer '{target.DisplayName}' wirklich entfernen?",
            "SENTINEL", MessageBoxButton.YesNo, MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes) return;

        var dialog = new ConfirmAdminPasswordDialog();
        if (dialog.ShowDialog() == true)
        {
            try
            {
                if (_users.RemoveUser(userId, dialog.Password))
                    RenderUsers();
                else
                    MessageBox.Show("Administrator-Passwort falsch.", "SENTINEL",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }

    private void ImportWindowsUsers_Click(object sender, RoutedEventArgs e)
    {
        if (GetCurrentUser()?.IsAdmin != true)
        {
            MessageBox.Show("Nur Administratoren dürfen Windows-Konten importieren.",
                "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            var accounts = Sentinel.Platform.Users.WindowsUserReader.GetImportableAccounts();

            if (accounts.Count == 0)
            {
                MessageBox.Show("Keine importierbaren Windows-Konten gefunden.",
                    "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new ImportWindowsUsersDialog(accounts);
            if (dialog.ShowDialog() != true) return;

            int imported = 0;
            foreach (var (account, password) in dialog.SelectedAccountsWithPasswords)
            {
                if (_users.Users.Any(u => u.DisplayName.Equals(account.Name, StringComparison.OrdinalIgnoreCase)))
                    continue; // schon vorhanden

                _users.AddUser(account.Name, password, account.IsAdministrator ? UserRole.Admin : UserRole.User);
                imported++;
            }

            RenderUsers();
            MessageBox.Show($"{imported} Windows-Konto(n) als Sentinel-Nutzer angelegt.",
                "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Import fehlgeschlagen: {ex.Message}",
                "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private UserAccount? GetCurrentUser()
    {
        // KEIN Fallback auf FirstOrDefault: ein unbekannter Nutzer bekommt
        // keine Rechte. Lieber „niemand" als versehentlich Admin.
        if (App.LoggedInUserName is not { Length: > 0 } name) return null;

        return _users.Users.FirstOrDefault(x =>
            x.DisplayName.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    private void Lock_Click(object sender, RoutedEventArgs e)
    {
        var lockWindow = new LockWindow();
        lockWindow.ShowDialog(); // bewusst ohne Ergebnis – Hauptfenster läuft weiter
    }

    // ---------- Export ----------

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_report is null) return;

        var dialog = new SaveFileDialog
        {
            Filter = "HTML-Bericht (*.html)|*.html|Textdatei (*.txt)|*.txt|Alle Dateien (*.*)|*.*",
            FileName = $"SENTINEL-Bericht_{DateTime.Now:yyyyMMdd_HHmm}.html"
        };

        if (dialog.ShowDialog() != true) return;

        try
        {
            string content = Path.GetExtension(dialog.FileName).ToLowerInvariant() == ".txt"
                ? ReportExporter.ToText(_report)
                : HtmlReportExporter.Render(_report);

            File.WriteAllText(dialog.FileName, content, System.Text.Encoding.UTF8);
            MessageBox.Show($"Bericht gespeichert:\n{dialog.FileName}", "SENTINEL",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Speichern fehlgeschlagen:\n{ex.Message}", "SENTINEL",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
