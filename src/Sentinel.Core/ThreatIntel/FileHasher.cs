using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Core.ThreatIntel;
public static class FileHasher
{
    public static async Task<string> ComputeSha256Async(string filePath, CancellationToken ct = default)
    {
        await using var stream = File.OpenRead(filePath);
        using var sha = SHA256.Create();
        var hash = await sha.ComputeHashAsync(stream, ct).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string ComputeSha256(byte[] content)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(content)).ToLowerInvariant();
    }
}

/// <summary>
/// Datei-Signaturprüfung: erkennt bekannte Dateitypen und verdächtige Merkmale
/// rein lokal – ohne Netz, ohne die Datei auszuführen.
/// </summary>
public static class LocalFileInspector
{
    private static readonly Dictionary<string, byte[]> Signatures = new()
    {
        ["Windows EXE (MZ)"] = new byte[] { 0x4D, 0x5A },
        ["Windows DLL"] = new byte[] { 0x4D, 0x5A }, // wie EXE – Kontext kommt aus Analyse
        ["ELF (Linux)"] = new byte[] { 0x7F, 0x45, 0x4C, 0x46 },
        ["PDF"] = new byte[] { 0x25, 0x50, 0x44, 0x46 },
        ["ZIP/Office-Dokument"] = new byte[] { 0x50, 0x4B, 0x03, 0x04 },
        ["PNG"] = new byte[] { 0x89, 0x50, 0x4E, 0x47 },
        ["JPEG"] = new byte[] { 0xFF, 0xD8, 0xFF },
        ["GIF"] = new byte[] { 0x47, 0x49, 0x46, 0x38 },
        ["Windows Script/HTA (text)"] = Encoding.ASCII.GetBytes("<script"),
        ["PowerShell-Skript-Header"] = Encoding.ASCII.GetBytes("powershell")
    };

    /// <summary>Erkennt den Dateityp anhand der Magic Bytes.</summary>
    public static string? DetectType(byte[] header)
    {
        foreach (var (name, magic) in Signatures)
        {
            if (header.Length >= magic.Length && header.AsSpan(0, magic.Length).SequenceEqual(magic))
                return name;
        }
        return null;
    }

    /// <summary>Prüft auf Merkmale, die eine genauere Prüfung rechtfertigen.</summary>
    public static List<string> AnalyzeRisks(byte[] content)
    {
        var risks = new List<string>();

        // Ausführbare Windows-Datei?
        if (content.Length >= 2 && content[0] == 0x4D && content[1] == 0x5A)
            risks.Add("Ausführbare Windows-Datei (EXE/DLL) – bei unbekannter Quelle niemals starten.");

        // Office-Dokumente mit Makros? (vbaProject.bin in ZIP)
        if (content.Length >= 4 && content[0] == 0x50 && content[1] == 0x4B)
        {
            if (Encoding.ASCII.GetString(content).Contains("vbaProject", StringComparison.OrdinalIgnoreCase))
                risks.Add("Office-Dokument enthält Makros (vbaProject). Makros aus unbekannten Quellen sind ein häufiger Malware-Weg.");
        }

        // Eingebettete PowerShell-Aufrufe im Text?
        string text = Encoding.ASCII.GetString(content.Take(Math.Min(content.Length, 64 * 1024)).ToArray());
        if (text.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("-enc ", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("downloadstring", StringComparison.OrdinalIgnoreCase))
            risks.Add("Datei enthält Verweise auf PowerShell-Befehle. Bei Skripten genau prüfen, bevor sie ausgeführt werden.");

        return risks;
    }

    /// <summary>Liest die ersten 512 Byte einer Datei für die Signaturprüfung.</summary>
    public static async Task<byte[]> ReadHeaderAsync(string filePath, int length = 512, CancellationToken ct = default)
    {
        await using var stream = File.OpenRead(filePath);
        var buffer = new byte[length];
        int read = await stream.ReadAsync(buffer.AsMemory(0, length), ct).ConfigureAwait(false);
        return buffer.AsSpan(0, read).ToArray();
    }
}
