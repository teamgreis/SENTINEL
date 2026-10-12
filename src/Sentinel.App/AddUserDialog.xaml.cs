using System.Windows;
using Sentinel.Core.Users;

namespace Sentinel.App;

public partial class AddUserDialog : Window
{
    public string UserName { get; private set; } = "";
    public string UserPassword { get; private set; } = "";

    public UserRole Role => RoleBox.SelectedIndex == 0 ? UserRole.Admin : UserRole.User;

    public AddUserDialog()
    {
        InitializeComponent();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Visibility = Visibility.Collapsed;

        string name = NameBox.Text?.Trim() ?? "";
        string pw = PasswordBox.Password;
        string confirm = ConfirmBox.Password;

        if (name.Length == 0)
        {
            ShowError("Name eingeben.");
            return;
        }

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

        UserName = name;
        UserPassword = pw;
        DialogResult = true;
        Close();
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }
}
