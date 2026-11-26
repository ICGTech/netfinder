using System.IO.Compression;
using System.Reflection;

namespace NetFinder.Core.Net;

/// <summary>MAC vendor lookup using the embedded IEEE OUI list.</summary>
public static class OuiLookup
{
    private static readonly Lazy<Dictionary<string, string>> Table = new(Load);

    private static Dictionary<string, string> Load()
    {
        var d = new Dictionary<string, string>(60000);
        try
        {
            using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("oui.txt.gz");
            if (s == null) return d;
            using var gz = new GZipStream(s, CompressionMode.Decompress);
            using var r = new StreamReader(gz);
            string? line;
            while ((line = r.ReadLine()) != null)
            {
                var tab = line.IndexOf('\t');
                if (tab == 6) d[line[..6]] = line[7..];
            }
        }
        catch { /* vendor lookup is optional */ }
        return d;
    }

    public static string? Lookup(string mac)
    {
        if (mac.Length < 8) return null;
        if (Mac.IsLocallyAdministered(mac)) return "(Random / private MAC)";
        var key = (mac[..2] + mac.Substring(3, 2) + mac.Substring(6, 2)).ToUpperInvariant();
        return Table.Value.TryGetValue(key, out var v) ? Tidy(v) : null;
    }

    private static string Tidy(string v)
    {
        // "HUAWEI TECHNOLOGIES CO.,LTD" -> "Huawei Technologies Co.,Ltd" (only for all-caps names)
        if (v.Any(char.IsLower)) return v;
        var words = v.ToLowerInvariant().Split(' ');
        for (var i = 0; i < words.Length; i++)
            if (words[i].Length > 0) words[i] = char.ToUpperInvariant(words[i][0]) + words[i][1..];
        return string.Join(' ', words);
    }
}
