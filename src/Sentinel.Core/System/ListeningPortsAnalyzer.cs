using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Sentinel.Core.System;

/// <summary>
/// Parst die Ausgabe von Get-NetTCPConnection für den Listening-Ports-Check.
/// Reine Logik – testbar ohne Windows.
/// </summary>
public static class ListeningPortsAnalyzer
{
    /// <summary>Ein lauschender Port.</summary>
    public sealed record ListeningPort(int Port, string State, string Process);
    /// <summary>
    /// Bekannte, potenziell riskante Ports (Remote-Access, Dateifreigabe etc.).
    /// </summary>
    public static readonly Dictionary<int, string> RiskyPorts = new()
    {
        [3389] = "Remote Desktop (RDP)",
        [5985] = "WinRM (HTTP)",
        [5986] = "WinRM (HTTPS)",
        [23] = "Telnet",
        [21] = "FTP",
        [445] = "SMB (Dateifreigabe)",
        [139] = "NetBIOS",
        [135] = "RPC-Endpunktzuordnung",
        [5900] = "VNC"
    };

    /// <summary>
    /// Analysiert eine Liste von „Port|State|Process"-Zeilen.
    /// Gibt die riskanten lauschenden Ports zurück.
    /// </summary>
    public static IReadOnlyList<ListeningPort> AnalyzeRisky(string text)
    {
        var result = new List<ListeningPort>();

        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Trim().Split('|');
            if (parts.Length < 3) continue;

            if (int.TryParse(parts[0].Trim(), out var port) &&
                parts[1].Trim().Equals("Listen", StringComparison.OrdinalIgnoreCase))
            {
                if (RiskyPorts.ContainsKey(port))
                    result.Add(new ListeningPort(port, parts[1].Trim(), parts[2].Trim()));
            }
        }

        return result;
    }
}
