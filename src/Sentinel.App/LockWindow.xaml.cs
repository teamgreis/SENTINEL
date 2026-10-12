using System.IO;
using Sentinel.Core;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Sentinel.Core.Users;
using Sentinel.Platform.Users;

namespace Sentinel.App;

public partial class LockWindow : Window
{
    static readonly string AppDataDir = Core.AppPaths.DataDir;

    private readonly UserManager _users;
    private readonly BackupKeyStore _backupKeys;
    private readonly IAuthenticationMethod _helloAuth;

    /// <summary>Name des erfolgreich angemeldeten Nutzers.</summary>
    public string? LoggedInUser { get; private set; }

    private UserAccount? SelectedUser =>
        UserComboBox.SelectedItem as UserAccount;

    public LockWindow()
    {
        InitializeComponent();

        _users = new UserManager(Path.Combine(AppDataDir, "users.json"));
        _backupKeys = new BackupKeyStore(Path.Combine(AppDataDir, "backupkeys.json"));
        _helloAuth = new WindowsHelloAuthentication();

        // Nutzer laden
        UserComboBox.ItemsSource = _users.Users;
        if (_users.Users.Count > 0)
            UserComboBox.SelectedIndex = 0;

        LockedSubtitle.Text = _users.Users.Count > 1
            ? "Nutzer auswählen und anmelden."
            : "Passwort eingeben oder Windows Hello nutzen.";

        // Windows-Hello-Button nur zeigen, wenn verfügbar
        HelloButton.Visibility = _helloAuth.IsAvailable
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private void UserComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SelectedUser is { } user)
            LockedTitle.Text = $"Willkommen zurück, {user.DisplayName}";
        PasswordBox.Password = "";
        ErrorText.Visibility = Visibility.Collapsed;
    }

    private void PasswordBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            UnlockButton_Click(sender, e);
    }

    private void BackupCodeBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            UnlockButton_Click(sender, e);
    }

    private void BackupButton_Click(object sender, RoutedEventArgs e)
    {
        bool show = BackupCodePanel.Visibility != Visibility.Visible;
        BackupCodePanel.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        BackupButton.Content = show ? "✕ Abbrechen" : "🔑 Backup-Code verwenden";
        if (show) BackupCodeBox.Focus();
    }

    private async void HelloButton_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedUser is null) return;

        ErrorText.Visibility = Visibility.Collapsed;
        HelloButton.IsEnabled = false;

        try
        {
            // Sicherheitshinweis: Windows Hello beweist, dass der physisch
            // anwesende Windows-Nutzer echt ist – nicht, WELCHER Sentinel-Nutzer
            // er ist. Deshalb wird Hello nur für den Sentinel-Nutzer akzeptiert,
            // dessen Name dem aktuellen Windows-Nutzer entspricht.
            string windowsUser = Environment.UserName;
            bool nameMatches = SelectedUser.DisplayName.Equals(windowsUser, StringComparison.OrdinalIgnoreCase);

            if (!nameMatches)
            {
                ShowError(
                    $"Windows Hello bestätigt den Windows-Nutzer '{windowsUser}', " +
                    $"nicht '{SelectedUser.DisplayName}'. Bitte das Passwort verwenden.");
                return;
            }

            bool ok = await _helloAuth.AuthenticateAsync(
                $"SENTINEL entsperren — {SelectedUser.DisplayName}");

            if (ok)
            {
                // Hello-Erfolg gilt als Nachweis; Nutzer wird angemeldet
                SelectedUser.LastLoginAt = DateTimeOffset.UtcNow;
                LoggedInUser = SelectedUser.DisplayName;
                DialogResult = true;
                Close();
            }
            else
            {
                ShowError("Windows Hello hat die Anmeldung nicht bestätigt.");
            }
        }
        finally
        {
            HelloButton.IsEnabled = true;
        }
    }

    private void UnlockButton_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Visibility = Visibility.Collapsed;

        if (SelectedUser is null)
        {
            ShowError("Kein Nutzer ausgewählt.");
            return;
        }

        // Backup-Code-Modus?
        if (BackupCodePanel.Visibility == Visibility.Visible)
        {
            string code = BackupCodeBox.Text?.Trim() ?? "";
            if (string.IsNullOrEmpty(code))
            {
                ShowError("Backup-Code eingeben.");
                return;
            }

            if (_backupKeys.TryConsume(SelectedUser.Id, code))
            {
                // Code gültig → Passwort zurücksetzen verlangen
                var reset = new ResetPasswordDialog(SelectedUser);
                if (reset.ShowDialog() == true && _users.ResetPassword(SelectedUser.Id, reset.NewPassword))
                {
                    MessageBox.Show(
                        "Passwort zurückgesetzt. Bitte merken – der Backup-Code ist jetzt verbraucht.",
                        "SENTINEL", MessageBoxButton.OK, MessageBoxImage.Information);
                    DialogResult = true;
                    Close();
                }
                else
                {
                    ShowError("Passwort konnte nicht gesetzt werden.");
                }
            }
            else
            {
                ShowError("Backup-Code ungültig oder bereits verbraucht.");
            }
            return;
        }

        // Passwort-Modus
        string password = PasswordBox.Password;
        if (string.IsNullOrEmpty(password))
        {
            ShowError("Passwort eingeben.");
            return;
        }

        var result = _users.Login(SelectedUser.DisplayName, password);

        switch (result)
        {
            case AuthResult.Success:
                LoggedInUser = SelectedUser.DisplayName;
                DialogResult = true;
                Close();
                return;

            case AuthResult.UserLocked:
                var remaining = _users.RemainingLockout(SelectedUser.Id);
                ShowError(remaining.HasValue
                    ? $"Zu viele Fehlversuche. Gesperrt für {remaining.Value.Minutes} Minuten."
                    : "Dieses Konto ist vorübergehend gesperrt.");
                return;

            case AuthResult.WrongPassword:
                // Hinweis auf verbleibende Versuche – ohne zu viel zu verraten
                var rem = _users.RemainingLockout(SelectedUser.Id);
                ShowError(rem.HasValue
                    ? $"Falsches Passwort. Konto gesperrt für {rem.Value.Minutes} Minuten."
                    : "Falsches Passwort.");
                return;

            default:
                ShowError("Anmeldung fehlgeschlagen.");
                return;
        }
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
        PasswordBox.Password = "";
        PasswordBox.Focus();
    }
}
