using System.Windows;

namespace Sentinel.App;

public partial class AdminResetPasswordDialog : Window
{
    public string NewPassword { get; private set; } = "";

    public AdminResetPasswordDialog(string userName)
    {
        InitializeComponent();
        Subtitle.Text = $"Setzt das Passwort für '{userName}' zurück. Der Nutzer muss danach das neue Passwort verwenden.";
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Visibility = Visibility.Collapsed;

        string pw = NewBox.Password;
        string confirm = ConfirmBox.Password;

        if (pw.Length < 8)
        {
            ShowError("Das Passwort muss mindestens 8 Zeichen haben.");
            return;
        }

        if (pw != confirm)
        {
            ShowError("Die Passwörter stimmen nicht überein.");
            return;
        }

        NewPassword = pw;
        DialogResult = true;
        Close();
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }
}
