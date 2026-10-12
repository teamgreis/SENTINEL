using System.Diagnostics;

namespace Sentinel.Platform.Checks;

/// <summary>Kapselt PowerShell-Aufrufe (read-only Abfragen).</summary>
internal static class PowerShell
{
    public static async Task<(string Output, string Error)> RunAsync(string script, CancellationToken ct)
    {
        // Sicherheits-Härtung: Skript läuft über stdin (-Command -), nicht über
        // die Kommandozeile. So kann kein Wert aus dem Skript in die Argumentkette
        // der Shell injizieren.
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException("PowerShell konnte nicht gestartet werden.");

        // Skript über stdin schreiben, dann Eingabe schließen
        await proc.StandardInput.WriteAsync(script.AsMemory(), ct).ConfigureAwait(false);
        proc.StandardInput.Close();

        string output = await proc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
        string error = await proc.StandardError.ReadToEndAsync(ct).ConfigureAwait(false);
        await proc.WaitForExitAsync(ct).ConfigureAwait(false);

        return (output.Trim(), error.Trim());
    }
}
