namespace Sentinel.Core.Settings;

/// <summary>
/// Anzeigenamen für die Designs. Liegt in Core (nicht im App-Projekt),
/// damit die Namen testbar sind und von UI und Tests gemeinsam genutzt werden.
/// </summary>
public static class ThemeNames
{
    /// <summary>Deutscher Anzeigename pro Design.</summary>
    public static string Display(ThemeMode mode) => mode switch
    {
        ThemeMode.Dark => "Sentinel Dark (Standard)",
        ThemeMode.Midnight => "Midnight (Nachtblau)",
        ThemeMode.DeepSpace => "DeepSpace (Neon-Grün)",
        ThemeMode.Solarized => "Solarized (Sepia)",
        ThemeMode.Mono => "Mono (Schwarz/Weiß, barrierefrei)",
        _ => "Sentinel Dark"
    };

    /// <summary>Kurzer Klartext-Hinweis pro Design (für die Einstellungsseite).</summary>
    public static string Hint(ThemeMode mode) => mode switch
    {
        ThemeMode.Dark => "Das Standard-Design: dunkles Violett mit Cyan-Akzenten.",
        ThemeMode.Midnight => "Tiefes Nachtblau — ruhiger für die Augen am Abend.",
        ThemeMode.DeepSpace => "Reines Schwarz mit Neon-Grün — Terminal-Optik.",
        ThemeMode.Solarized => "Warme Sepia-Töne auf Dunkelbraun.",
        ThemeMode.Mono => "Komplett farbfrei, maximaler Kontrast. Gedacht für Farbsehschwäche und Barrierefreiheit.",
        _ => ""
    };
}
