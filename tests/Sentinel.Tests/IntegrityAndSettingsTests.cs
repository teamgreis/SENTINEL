using Sentinel.Core.Integrity;
using Sentinel.Core.Settings;
using Xunit;

namespace Sentinel.Tests;

public class IntegrityVerifierTests : IDisposable
{
    private readonly string _dir;

    public IntegrityVerifierTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"sentinel_int_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private void WriteFile(string name, string content)
    {
        File.WriteAllText(Path.Combine(_dir, name), content);
    }

    [Fact]
    public void IntactFiles_ReportIntact()
    {
        WriteFile("Sentinel.exe", "original");
        WriteFile("Core.dll", "original-core");

        var manifest = IntegrityVerifier.CreateManifest(_dir, new[] { "Sentinel.exe", "Core.dll" });
        var report = IntegrityVerifier.Verify(_dir, manifest);

        Assert.True(report.IsIntact);
        Assert.False(report.HasModified);
        Assert.Contains("unverändert", report.Summary);
    }

    [Fact]
    public void ModifiedFile_IsDetected()
    {
        WriteFile("Sentinel.exe", "original");
        var manifest = IntegrityVerifier.CreateManifest(_dir, new[] { "Sentinel.exe" });

        // Manipulation!
        WriteFile("Sentinel.exe", "MANIPULIERT");

        var report = IntegrityVerifier.Verify(_dir, manifest);

        Assert.False(report.IsIntact);
        Assert.True(report.HasModified);
        Assert.Contains(report.Problems, f =>
            f.Status == FileIntegrityStatus.Modified && f.FileName == "Sentinel.exe");
    }

    [Fact]
    public void MissingFile_IsDetected()
    {
        WriteFile("Core.dll", "inhalt");
        var manifest = IntegrityVerifier.CreateManifest(_dir, new[] { "Core.dll" });

        File.Delete(Path.Combine(_dir, "Core.dll"));

        var report = IntegrityVerifier.Verify(_dir, manifest);

        Assert.True(report.HasMissing);
    }

    [Fact]
    public void NewExecutable_IsDetected()
    {
        WriteFile("Sentinel.exe", "original");
        var manifest = IntegrityVerifier.CreateManifest(_dir, new[] { "Sentinel.exe" });

        // Unbekannte DLL eingeschleust
        WriteFile("evil.dll", "payload");

        var report = IntegrityVerifier.Verify(_dir, manifest);

        Assert.True(report.HasNew);
        Assert.Contains(report.Problems, f =>
            f.Status == FileIntegrityStatus.New && f.FileName == "evil.dll");
    }

    [Fact]
    public void ManifestRoundTrips()
    {
        WriteFile("a.exe", "inhalt");
        var manifest = IntegrityVerifier.CreateManifest(_dir, new[] { "a.exe" });

        IntegrityVerifier.SaveManifest(_dir, manifest);
        var loaded = IntegrityVerifier.LoadManifest(_dir);

        Assert.NotNull(loaded);
        Assert.Equal(manifest.Entries["a.exe"], loaded!.Entries["a.exe"]);
    }

    [Fact]
    public void LoadMissingManifest_ReturnsNull()
    {
        Assert.Null(IntegrityVerifier.LoadManifest(_dir));
    }

    [Fact]
    public void CorruptManifest_ReturnsNull()
    {
        File.WriteAllText(Path.Combine(_dir, IntegrityVerifier.ManifestFileNameConst), "kaputt{{{");
        Assert.Null(IntegrityVerifier.LoadManifest(_dir));
    }

    [Fact]
    public void HashIsSha256()
    {
        WriteFile("test.txt", "hello");
        var hash = IntegrityVerifier.ComputeFileHash(Path.Combine(_dir, "test.txt"));

        Assert.Equal(64, hash.Length); // SHA-256 = 32 Byte = 64 Hex-Zeichen
        Assert.Equal(hash, hash.ToLowerInvariant());
    }
}

public class AppSettingsTests : IDisposable
{
    private readonly string _path;

    public AppSettingsTests()
    {
        _path = Path.Combine(Path.GetTempPath(), $"sentinel_settings_{Guid.NewGuid():N}.json");
    }

    public void Dispose()
    {
        try { if (File.Exists(_path)) File.Delete(_path); } catch { }
    }

    [Fact]
    public void DefaultValues_AreSafe()
    {
        var settings = new AppSettings();

        Assert.False(settings.TelemetryEnabled);
        Assert.False(settings.OnlineChecksEnabled);
        Assert.True(settings.IntegrityCheckOnStart);
        Assert.True(settings.BlockIfManipulated);
        Assert.True(settings.RequirePasswordOnStart);
    }

    [Fact]
    public void SaveAndLoad_RoundTrips()
    {
        var settings = new AppSettings
        {
            Theme = ThemeMode.Midnight,
            OnlineChecksEnabled = true,
            LockAfterMinutes = 30,
            AutoExportReport = true
        };
        settings.Save(_path);

        var loaded = AppSettings.Load(_path);

        Assert.Equal(ThemeMode.Midnight, loaded.Theme);
        Assert.True(loaded.OnlineChecksEnabled);
        Assert.Equal(30, loaded.LockAfterMinutes);
        Assert.True(loaded.AutoExportReport);
    }

    [Fact]
    public void LoadMissingFile_ReturnsDefaults()
    {
        var loaded = AppSettings.Load(Path.Combine(Path.GetTempPath(), $"nope_{Guid.NewGuid():N}.json"));

        Assert.False(loaded.TelemetryEnabled);
        Assert.True(loaded.CheckOnStartup);
    }

    [Fact]
    public void CorruptFile_ReturnsDefaults()
    {
        File.WriteAllText(_path, "kein json{{{");
        var loaded = AppSettings.Load(_path);

        Assert.True(loaded.IntegrityCheckOnStart);
    }

    [Fact]
    public void Reset_RestoresDefaults()
    {
        var settings = new AppSettings { OnlineChecksEnabled = true, LockAfterMinutes = 999 };
        settings.Reset();

        Assert.False(settings.OnlineChecksEnabled);
        Assert.Equal(15, settings.LockAfterMinutes);
    }

    [Fact]
    public void HasEnoughSettings()
    {
        Assert.True(AppSettings.SettingCount >= 25,
            $"Erwartet mindestens 25 Einstellungen, hat {AppSettings.SettingCount}");
    }
}
