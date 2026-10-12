using System.Windows;

namespace Sentinel.App;

public partial class ChangePasswordDialog : Window
{
    public string CurrentPassword { get; private set; } = string.Empty;
    public string NewPassword { get; private set; } = string.Empty;

    public ChangePasswordDialog()
    {
        InitializeComponent();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void Change_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Visibility = Visibility.Collapsed;

        string current = CurrentBox.Password;
        string newPw = NewBox.Password;
        string confirm = ConfirmBox.Password;

        if (string.IsNullOrEmpty(current))
        {
            ShowError("Aktuelles Passwort eingeben.");
            return;
        }

        if (newPw.Length < 8)
        {
            ShowError("Das neue Passwort muss mindestens 8 Zeichen haben.");
            return;
        }

        if (newPw != confirm)
        {
            ShowError("Die neuen Passwörter stimmen nicht überein.");
            return;
        }

        CurrentPassword = current;
        NewPassword = newPw;
        DialogResult = true;
        Close();
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }
}
