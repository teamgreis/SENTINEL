using System.IO;
using Sentinel.Core;
using System.Windows;
using Sentinel.Core.Integrity;
using Sentinel.Core.Users;

namespace Sentinel.App;

public partial class OnboardingWindow : Window
{
    static readonly string AppDataDir = Core.AppPaths.DataDir;

    private UserAccount? _createdUser;

    public OnboardingWindow()
    {
        InitializeComponent();
    }

    private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        var strength = PasswordHasher.ScoreStrength(PasswordBox.Password);

        StrengthBar.Foreground = strength.Score switch
        {
            >= 80 => (System.Windows.Media.Brush)FindResource("Green"),
            >= 60 => (System.Windows.Media.Brush)FindResource("Amber"),
            _ => (System.Windows.Media.Brush)FindResource("Red")
        };

        StrengthBar.Text = strength.Score > 0
            ? $"Stärke: {strength.Label} ({strength.Score}/100)"
            : "";
    }

    private void Create_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Visibility = Visibility.Collapsed;

        string name = NameBox.Text.Trim();
        string password = PasswordBox.Password;
        string confirm = PasswordConfirmBox.Password;

        if (string.IsNullOrWhiteSpace(name))
        {
            ShowError("Bitte einen Anzeigenamen eingeben.");
            return;
        }

        if (password.Length < 8)
        {
            ShowError("Das Passwort muss mindestens 8 Zeichen haben.");
            return;
        }

        if (password != confirm)
        {
            ShowError("Die Passwörter stimmen nicht überein.");
            return;
        }

        try
        {
            var users = new UserManager(Path.Combine(AppDataDir, "users.json"));

            // Erster Nutzer = immer Admin
            _createdUser = users.CreateFirstUser(name, password);

            // Backup-Codes erzeugen
            var backupStore = new BackupKeyStore(Path.Combine(AppDataDir, "backupkeys.json"));
            var codes = backupStore.CreateForUser(_createdUser.Id, 2);

            BackupKey1Text.Text = codes[0];
            BackupKey2Text.Text = codes[1];
            BackupPanel.Visibility = Visibility.Visible;

            // Formular ausblenden, Button ändern
            CreateButton.Visibility = Visibility.Collapsed;
            BackupPanel.BringIntoView();

            // Erststart: Integritäts-Manifest der App erzeugen
            CreateInitialManifest();
        }
        catch (Exception ex)
        {
            ShowError($"Konto konnte nicht erstellt werden: {ex.Message}");
        }
    }

    private void Finish_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }

    /// <summary>Erzeugt beim ersten Start das Signatur-Manifest der eigenen Dateien.</summary>
    private static void CreateInitialManifest()
    {
        try
        {
            string appDir = AppContext.BaseDirectory;
            if (IntegrityVerifier.LoadManifest(appDir) is not null) return;

            var ownFiles = Directory.EnumerateFiles(appDir, "Sentinel*.dll")
                .Concat(Directory.EnumerateFiles(appDir, "Sentinel.exe"))
                .Select(Path.GetFileName)
                .Where(n => n is not null)
                .Cast<string>()
                .ToList();

            var manifest = IntegrityVerifier.CreateManifest(appDir, ownFiles);
            IntegrityVerifier.SaveManifest(appDir, manifest);
        }
        catch
        {
            // Manifest-Erzeugung darf das Onboarding nie blockieren
        }
    }
}
