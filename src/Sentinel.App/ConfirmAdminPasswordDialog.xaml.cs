using System.Windows;
using System.Windows.Input;

namespace Sentinel.App;

public partial class ConfirmAdminPasswordDialog : Window
{
    public string Password => PasswordBox.Password;

    public ConfirmAdminPasswordDialog()
    {
        InitializeComponent();
    }

    private void PasswordBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            Ok_Click(sender, e);
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(PasswordBox.Password))
        {
            ErrorText.Text = "Passwort eingeben.";
            ErrorText.Visibility = Visibility.Visible;
            return;
        }

        DialogResult = true;
        Close();
    }
}
