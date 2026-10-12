using System.Windows;
using Sentinel.Core;

namespace Sentinel.App;

public partial class InfoDialog : Window
{
    public InfoDialog()
    {
        InitializeComponent();

        // Kopf
        VersionText.Text = $"Version {Branding.FullVersion} — {Branding.Tagline}";
        CreditText.Text = $"© {Branding.Author} · Hacker-Name: {Branding.AuthorAlias} · Lizenz: MIT";

        // Über
        DescText.Text = ProgramInfo.Description;
        ConceptList.ItemsSource = ProgramInfo.Concept;
        LimitationsList.ItemsSource = ProgramInfo.Limitations;

        // Änderungsprotokoll
        ChangelogList.ItemsSource = ProgramInfo.Changelog;

        // Lizenz
        LicenseText.Text = ProgramInfo.License;
    }

    private void OpenManual_Click(object sender, RoutedEventArgs e)
    {
        var manual = new ManualWindow { Owner = this };
        manual.ShowDialog();
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
    }
}
