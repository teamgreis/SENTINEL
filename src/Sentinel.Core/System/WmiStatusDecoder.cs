using System.Text.Json;

namespace Sentinel.Core.System;

/// <summary>
/// Dekodiert den productState-Wert aus WMI SecurityCenter2.
/// Die Bitbelegung ist von Microsoft dokumentiert:
/// - Bit 12 (0x1000): Sicherheitsprodukt EINgeschaltet
/// - Bit 8  (0x0100): Echtzeitschutz aktiv
/// - Bit 4  (0x0010): Signaturen aktuell (nicht veraltet)
/// </summary>
public static class WmiStatusDecoder
{
    private const int ProductOnBit = 0x1000;
    private const int RealtimeBit = 0x0100;
    private const int SignaturesFreshBit = 0x0010;

    public static bool IsEnabled(int productState) => (productState & ProductOnBit) != 0;
    public static bool IsRealtimeProtectionOn(int productState) => (productState & RealtimeBit) != 0;
    public static bool AreSignaturesStale(int productState) => (productState & SignaturesFreshBit) == 0;
}

/// <summary>Ein erkanntes Antivirus-Produkt aus WMI.</summary>
public sealed record AvProduct
{
    public string DisplayName { get; init; } = string.Empty;
    public int ProductState { get; init; }
}

/// <summary>Parst die JSON-Ausgabe der WMI-Abfrage.</summary>
public static class WmiParser
{
    public static bool TryParse(string json, out List<AvProduct> products)
    {
        products = new List<AvProduct>();
        if (string.IsNullOrWhiteSpace(json)) return false;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.ValueKind == JsonValueKind.Object)
                Add(root, products);
            else if (root.ValueKind == JsonValueKind.Array)
                foreach (var item in root.EnumerateArray()) Add(item, products);

            return true;
        }
        catch
        {
            return false;
        }

        static void Add(JsonElement e, List<AvProduct> list)
        {
            string name = e.TryGetProperty("displayName", out var n) ? n.GetString() ?? "" : "";
            int state = e.TryGetProperty("productState", out var p) && p.ValueKind == JsonValueKind.Number
                ? p.GetInt32() : 0;
            list.Add(new AvProduct { DisplayName = name, ProductState = state });
        }
    }
}
