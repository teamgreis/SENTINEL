using System.IO;
using Sentinel.Core;
using System.Windows;
using Sentinel.Core.Integrity;
using Sentinel.Core.Users;

namespace Sentinel.App;

public partial class App : Application
{
    static readonly string AppDataDir = Core.AppPaths.DataDir;

    /// <summary>Name des an der Sperre angemeldeten Nutzers (für das Hauptfenster).</summary>
    public static string? LoggedInUserName { get; set; }

    private void App_OnStartup(object sender, StartupEventArgs e)
    {
        Directory.CreateDirectory(AppDataDir);

        // Startup-Check-Modus: still, für den Windows-Autostart-Task
        if (e.Args.Contains("--startup-check"))
        {
            RunStartupCheck();
            Shutdown();
            return;
        }

        // 1. Integrität prüfen (falls Manifest existiert)
        var settings = Core.Settings.AppSettings.Load(Path.Combine(AppDataDir, "settings.json"));
        if (settings.IntegrityCheckOnStart)
        {
            var report = CheckIntegrity();
            if (report is not null && !report.IsIntact && settings.BlockIfManipulated)
            {
                MessageBox.Show(
                    $"SENTINEL hat Manipulationen an seinen eigenen Dateien erkannt und wird beendet.\n\n{report.Summary}\n\n" +
                    "Details:\n" + string.Join("\n", report.Problems.Select(p => $"• {p.FileName}: {p.Status}")),
                    "SENTINEL — Sicherheitswarnung", MessageBoxButton.OK, MessageBoxImage.Stop);
                Shutdown();
                return;
            }
        }

        // 2. Onboarding oder Sperre
        var users = new UserManager(Path.Combine(AppDataDir, "users.json"));

        if (!users.HasUsers)
        {
            // Reset-Erkennung: war SENTINEL mal eingerichtet, sind die Daten aber weg?
            var resetDetector = new ResetDetector(AppDataDir);
            var resetCheck = resetDetector.Check(hasUserData: false);

            if (resetCheck.WasReset)
            {
                MessageBox.Show(
                    resetCheck.Message + "\n\n" +
                    "Alle Nutzer, Einstellungen und der Verlauf wurden durch den Windows-Reset gelöscht. " +
                    "Richte SENTINEL neu ein.",
                    "SENTINEL — Neueinrichtung erforderlich",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }

            // Erststart/Reset: Onboarding (legt Admin + Backup-Codes an)
            var onboarding = new OnboardingWindow();
            if (onboarding.ShowDialog() != true)
            {
                Shutdown();
                return;
            }

            // Nach erfolgreichem Onboarding Marker setzen
            new ResetDetector(AppDataDir).MarkInstalled();
        }
        else
        {
            // Marker sicherstellen (für spätere Reset-Erkennung)
            new ResetDetector(AppDataDir).MarkInstalled();

            // Jeder Start: Sperre bis Anmeldung (Passwort / Hello / Backup)
            var lockWindow = new LockWindow();
            if (lockWindow.ShowDialog() != true)
            {
                Shutdown();
                return;
            }

            // Angemeldeten Nutzer an das Hauptfenster weiterreichen
            if (lockWindow.LoggedInUser is { Length: > 0 } loggedIn)
                LoggedInUserName = loggedIn;
        }

        // 3. Hauptfenster
        var main = new MainWindow();
        main.Show();
    }

    private static void RunStartupCheck()
    {
        try
        {
            var settings = Core.Settings.AppSettings.Load(Path.Combine(AppDataDir, "settings.json"));
            if (!settings.StartupCheckOnWindowsBoot) return;

            var users = new UserManager(Path.Combine(AppDataDir, "users.json"));
            if (!users.HasUsers) return; // noch nicht eingerichtet

            // Integrität
            var report = CheckIntegrity();
            if (report is { IsIntact: false } && settings.BlockIfManipulated)
            {
                Notify("SENTINEL: Manipulation an Programmdateien erkannt. Details in der App.");
                return;
            }

            // Quick-Scan im Hintergrund
            var runner = new Core.Reporting.ScanRunner(Platform.CheckRegistry.CreateDefault());
            var scan = runner.RunAsync().GetAwaiter().GetResult();

            var logPath = Path.Combine(AppDataDir, "startup-check.log");
            File.AppendAllText(logPath,
                $"[{scan.FinishedAt:yyyy-MM-dd HH:mm}] Startup-Check: Score {scan.Score.Value}/100 ({scan.Score.Grade}), " +
                $"{scan.Score.Failed} Probleme, {scan.Score.Warnings} Hinweise\n");

            if (scan.Score.Value < 50 && settings.ShowStartupNotification)
                Notify($"SENTINEL-Startprüfung: Score nur {scan.Score.Value}/100. App für Details öffnen.");
            else if (scan.Score.Failed > 0 && settings.ShowStartupNotification)
                Notify($"SENTINEL-Startprüfung: {scan.Score.Failed} Problem(e) gefunden. App für Details öffnen.");
        }
        catch
        {
            // Startup-Check darf Windows nie stören
        }
    }

    private static void Notify(string message)
    {
        try
        {
            var settings = Core.Settings.AppSettings.Load(Path.Combine(AppDataDir, "settings.json"));
            if (settings.StartupCheckQuietMode) return;
            MessageBox.Show(message, "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch { }
    }

    private static Core.Integrity.IntegrityReport? CheckIntegrity()
    {
        try
        {
            string appDir = AppContext.BaseDirectory;
            var manifest = IntegrityVerifier.LoadManifest(appDir);
            if (manifest is null) return null;
            return IntegrityVerifier.Verify(appDir, manifest);
        }
        catch
        {
            return null;
        }
    }
}
