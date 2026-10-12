using System.Text.RegularExpressions;

namespace Sentinel.Core.System;

/// <summary>
/// Extrahiert ScreenSaveActive und ScreenSaveTimeOut aus PowerShell-Textausgabe.
/// Reine Logik – testbar ohne Windows.
/// </summary>
public static class ScreenLockParser
{
    public static (bool? Active, int? TimeoutSeconds) Parse(string output)
    {
        if (string.IsNullOrWhiteSpace(output)) return (null, null);

        bool? active = null;
        int? timeout = null;

        var activeMatch = Regex.Match(output, @"ScreenSaveActive\s*[:=]\s*(\d+)", RegexOptions.IgnoreCase);
        if (activeMatch.Success && int.TryParse(activeMatch.Groups[1].Value, out var a))
            active = a == 1;

        var timeoutMatch = Regex.Match(output, @"ScreenSaveTimeOut\s*[:=]\s*(\d+)", RegexOptions.IgnoreCase);
        if (timeoutMatch.Success && int.TryParse(timeoutMatch.Groups[1].Value, out var t))
            timeout = t;

        return (active, timeout);
    }
}
