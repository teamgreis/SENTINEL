using Sentinel.Core;
using Sentinel.Core.Settings;
using Xunit;

namespace Sentinel.Tests;

public class ThemeModeTests
{
    [Fact]
    public void AllModes_HaveDisplayNames()
    {
        foreach (var mode in Enum.GetValues<ThemeMode>())
        {
            string name = ThemeNames.Display(mode);
            Assert.False(string.IsNullOrWhiteSpace(name));
            Assert.Contains(mode.ToString(), name, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void EveryMode_HasHint()
    {
        foreach (var mode in Enum.GetValues<ThemeMode>())
        {
            string hint = ThemeNames.Hint(mode);
            Assert.False(string.IsNullOrWhiteSpace(hint), $"Kein Hinweis für {mode}");
        }
    }

    [Fact]
    public void FiveModes_Exist()
    {
        Assert.Equal(5, Enum.GetValues<ThemeMode>().Length);
    }

    [Fact]
    public void Mono_IsLast()
    {
        // Mono soll als barrierefreies Extra am Ende stehen
        var values = Enum.GetValues<ThemeMode>();
        Assert.Equal(ThemeMode.Mono, values[^1]);
    }
}

public class ProgramInfoTests
{
    [Fact]
    public void Description_NotEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(ProgramInfo.Description));
        Assert.Contains("SENTINEL", ProgramInfo.Description);
    }

    [Fact]
    public void Concept_HasEntries()
    {
        Assert.True(ProgramInfo.Concept.Length >= 5);
        foreach (var c in ProgramInfo.Concept)
            Assert.False(string.IsNullOrWhiteSpace(c));
    }

    [Fact]
    public void Limitations_Honest()
    {
        Assert.True(ProgramInfo.Limitations.Length >= 3);
        // Muss ehrlich sagen, dass es kein Antivirus ist
        Assert.Contains(ProgramInfo.Limitations,
            l => l.Contains("Defender", StringComparison.OrdinalIgnoreCase) ||
                 l.Contains("Antivirus", StringComparison.OrdinalIgnoreCase) ||
                 l.Contains("Antiviren", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void License_IsProprietary()
    {
        // Kurzfassung muss die Kernpunkte nennen
        Assert.Contains("Proprietäre Nutzungslizenz", ProgramInfo.LicenseShort);
        Assert.Contains("nicht-kommerzielle", ProgramInfo.LicenseShort);
        Assert.Contains("Fork", ProgramInfo.LicenseShort);
        Assert.Contains("Kommerzielle Nutzung", ProgramInfo.LicenseShort, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Felix Greis", ProgramInfo.LicenseShort);
        Assert.Contains("Elian", ProgramInfo.LicenseShort);

        // Deutsches Recht und Datenschutz müssen referenziert sein
        Assert.Contains("Bundesrepublik Deutschland", ProgramInfo.LicenseShort);
        Assert.Contains("DSGVO", ProgramInfo.LicenseShort);
        Assert.Contains("TDDDG", ProgramInfo.LicenseShort);
    }

    [Fact]
    public void License_NotOpenSource()
    {
        // Die alte MIT-Formulierung darf nicht mehr drin stehen
        Assert.DoesNotContain("Permission is hereby granted", ProgramInfo.LicenseShort);
        Assert.DoesNotContain("MIT License", ProgramInfo.LicenseShort);
        // Anzeigename darf nicht mehr MIT sein
        Assert.DoesNotContain("MIT", ProgramInfo.LicenseName);
    }

    [Fact]
    public void Changelog_NewestFirst()
    {
        Assert.True(ProgramInfo.Changelog.Length >= 4);
        Assert.Equal("2.5 Beta", ProgramInfo.Changelog[0].Version);
        // Neueste zuerst prüfen
        for (int i = 1; i < ProgramInfo.Changelog.Length; i++)
        {
            Assert.True(
                string.CompareOrdinal(ProgramInfo.Changelog[i - 1].Version, ProgramInfo.Changelog[i].Version) > 0,
                $"Changelog nicht absteigend bei Index {i}");
        }
    }

    [Fact]
    public void Changelog_25HasThemeEntry()
    {
        var latest = ProgramInfo.Changelog[0];
        Assert.Contains(latest.Changes, c => c.Contains("Design") || c.Contains("Theme", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Manual_CoversCoreWorkflows()
    {
        var titles = ProgramInfo.Manual.Select(m => m.Title).ToArray();
        Assert.Contains("Erste Schritte", titles);
        Assert.Contains("Anmelden", titles);
        Assert.Contains("Design wechseln", titles);
        Assert.Contains("Was SENTINEL nicht kann", titles);

        foreach (var chapter in ProgramInfo.Manual)
        {
            Assert.True(chapter.Steps.Length >= 3, $"Kapitel '{chapter.Title}' hat zu wenige Schritte");
            foreach (var step in chapter.Steps)
                Assert.False(string.IsNullOrWhiteSpace(step));
        }
    }

    [Fact]
    public void Branding_IsCorrect()
    {
        Assert.Equal("SENTINEL", Branding.ProductName);
        Assert.Equal("2.5", Branding.Version);
        Assert.Equal("Beta", Branding.Stage);
        Assert.Equal("Felix Greis", Branding.Author);
        Assert.Equal("Elian", Branding.AuthorAlias);
    }
}
