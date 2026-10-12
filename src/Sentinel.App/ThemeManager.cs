using System.Windows;

namespace Sentinel.App;

/// <summary>
/// Verwaltet die Design-Umschaltung. Die Farb-Tokens liegen in
/// Themes/Theme.&lt;Name&gt;.xaml; dieses Dictionary wird zur Laufzeit
/// gegen die MergedDictionaries der App getauscht. Die Styles in Theme.xaml
/// verweisen per StaticResource auf die Token-Keys – deshalb wirkt der
/// Tausch sofort auf die gesamte Oberfläche.
/// </summary>
public static class ThemeManager
{
    /// <summary>Anzeigename pro Design (deutsch, für die Einstellungsseite).</summary>
    public static string DisplayName(Core.Settings.ThemeMode mode) => Core.Settings.ThemeNames.Display(mode);

    /// <summary>Dateiname des Design-Dictionarys.</summary>
    public static string DictionaryName(Core.Settings.ThemeMode mode) => mode switch
    {
        Core.Settings.ThemeMode.Dark => "Theme.Dark.xaml",
        Core.Settings.ThemeMode.Midnight => "Theme.Midnight.xaml",
        Core.Settings.ThemeMode.DeepSpace => "Theme.DeepSpace.xaml",
        Core.Settings.ThemeMode.Solarized => "Theme.Solarized.xaml",
        Core.Settings.ThemeMode.Mono => "Theme.Mono.xaml",
        _ => "Theme.Dark.xaml"
    };

    /// <summary>Alle Designs in Anzeige-Reihenfolge.</summary>
    public static IReadOnlyList<Core.Settings.ThemeMode> All { get; } = new[]
    {
        Core.Settings.ThemeMode.Dark,
        Core.Settings.ThemeMode.Midnight,
        Core.Settings.ThemeMode.DeepSpace,
        Core.Settings.ThemeMode.Solarized,
        Core.Settings.ThemeMode.Mono
    };

    private static ResourceDictionary? _activeTheme;

    /// <summary>Aktuell geladenes Design (für Tests/Diagnose).</summary>
    public static string? ActiveThemeName => _activeTheme?.Source?.OriginalString;

    /// <summary>
    /// Lädt ein Design. Gibt false zurück, wenn das Dictionary nicht
    /// gefunden wurde – dann bleibt das bisherige aktiv (kein Blindflug).
    /// </summary>
    public static bool Apply(Core.Settings.ThemeMode mode)
    {
        var app = Application.Current;
        if (app?.Resources is null) return false;

        string name = DictionaryName(mode);
        var uri = new Uri($"Themes/{name}", UriKind.Relative);

        ResourceDictionary? newDict;
        try
        {
            newDict = new ResourceDictionary { Source = uri };
            // Probe: erwarteter Token muss da sein
            if (!newDict.Contains("BgColor")) return false;
        }
        catch
        {
            return false;
        }

        // Altes Design-Dictionary entfernen
        if (_activeTheme is not null)
            app.Resources.MergedDictionaries.Remove(_activeTheme);

        app.Resources.MergedDictionaries.Add(newDict);
        _activeTheme = newDict;
        return true;
    }

    /// <summary>Parst einen Design-Namen sicher (unbekannt → Dark).</summary>
    public static Core.Settings.ThemeMode Parse(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return Core.Settings.ThemeMode.Dark;
        return Enum.TryParse<Core.Settings.ThemeMode>(name, ignoreCase: true, out var mode)
            && All.Contains(mode)
            ? mode
            : Core.Settings.ThemeMode.Dark;
    }
}
