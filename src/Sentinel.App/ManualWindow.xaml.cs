using System.Windows;
using Sentinel.Core;

namespace Sentinel.App;

public partial class ManualWindow : Window
{
    public ManualWindow()
    {
        InitializeComponent();

        ChapterList.ItemsSource = ProgramInfo.Manual;
        FooterText.Text = $"SENTINEL {Branding.FullVersion} · © {Branding.Author} ({Branding.AuthorAlias})";
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
    }
}
