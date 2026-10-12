using System.Text.Json;

namespace Sentinel.Core.ThreatIntel;

/// <summary>
/// Verwaltet die Einwilligung des Nutzers für Online-Prüfungen.
/// Gespeichert wird nur ein JA/NEIN – keinerlei Nutzungsdaten.
/// Ohne aktive Einwilligung wird NICHTS nach außen gesendet.
/// </summary>
public sealed class ConsentSettings
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    private readonly string _filePath;
    private bool _onlineAllowed;

    public ConsentSettings(string filePath)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        _onlineAllowed = Load();
    }

    /// <summary>Hat der Nutzer Online-Prüfungen erlaubt?</summary>
    public bool OnlineAllowed => _onlineAllowed;

    public void SetOnlineAllowed(bool allowed)
    {
        _onlineAllowed = allowed;
        Save();
    }

    private bool Load()
    {
        try
        {
            if (!File.Exists(_filePath)) return false;
            var json = File.ReadAllText(_filePath);
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("onlineAllowed", out var v) &&
                   (v.ValueKind == JsonValueKind.True);
        }
        catch
        {
            return false;
        }
    }

    private void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(_filePath));
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            File.WriteAllText(_filePath, JsonSerializer.Serialize(new { onlineAllowed = _onlineAllowed }, Options));
        }
        catch
        {
            // Speichern der Einwilligung darf die App nicht crashen
        }
    }
}
