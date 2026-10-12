namespace Sentinel.Core;

/// <summary>Globale Produkt-Informationen (Branding).</summary>
public static class Branding
{
    public const string ProductName = "SENTINEL";
    public const string Version = "2.3";
    public const string Stage = "Beta";
    public const string Author = "Felix Greis";
    public const string AuthorAlias = "Elian";
    public const string Tagline = "Protect. Detect. Understand.";

    public static string FullVersion => $"{Version} {Stage}";
    public static string Credit => $"© {Author} (Alias: {AuthorAlias})";
}
