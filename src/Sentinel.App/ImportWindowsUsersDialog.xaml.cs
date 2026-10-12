using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using Sentinel.Platform.Users;
using WindowsAccount = Sentinel.Platform.Users.WindowsUserReader.WindowsAccount;

namespace Sentinel.App;

public partial class ImportWindowsUsersDialog : Window
{
    public ObservableCollection<AccountRow> Rows { get; } = new();

    public IEnumerable<(WindowsAccount Account, string Password)> SelectedAccountsWithPasswords =>
        Rows.Where(r => r.Selected)
            .Select(r => (r.Account, PasswordBox.Password))
            .ToList();

    public ImportWindowsUsersDialog(IReadOnlyList<WindowsAccount> accounts)
    {
        InitializeComponent();

        foreach (var a in accounts)
        {
            Rows.Add(new AccountRow
            {
                Account = a,
                Name = a.Name,
                Detail = a.IsAdministrator
                    ? "Windows-Administrator → Sentinel-Admin"
                    : "Windows-Nutzer → Sentinel-Nutzer",
                Selected = false
            });
        }

        AccountList.ItemsSource = Rows;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Visibility = Visibility.Collapsed;

        var selected = Rows.Where(r => r.Selected).ToList();

        if (selected.Count == 0)
        {
            ShowError("Mindestens ein Konto auswählen.");
            return;
        }

        if (PasswordBox.Password.Length < 8)
        {
            ShowError("Das Passwort muss mindestens 8 Zeichen haben.");
            return;
        }

        DialogResult = true;
        Close();
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }

    public sealed class AccountRow
    {
        public WindowsAccount Account { get; set; } = null!;
        public string Name { get; set; } = "";
        public string Detail { get; set; } = "";
        public bool Selected { get; set; }
    }
}
