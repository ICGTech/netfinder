using System.Text.RegularExpressions;

namespace NetFinder.Core.Model;

/// <summary>Picks the Log lines about one device: its IP as a whole word (10.0.0.1 is not 10.0.0.12), its MAC, or its name.</summary>
public static class LogFilter
{
    public static Regex? For(string? ip, string? mac, IEnumerable<string?> names, bool self)
    {
        var parts = new List<string>();
        if (!string.IsNullOrEmpty(ip)) parts.Add($@"(?<![\d.]){Regex.Escape(ip)}(?![\d])");
        if (mac is { Length: 17 }) parts.Add(Regex.Escape(mac).Replace(":", "[:-]"));
        foreach (var n in names)
            if (n?.Split('.')[0].Trim() is { Length: >= 4 } s && s != "*") parts.Add($@"(?<![\w-]){Regex.Escape(s)}(?![\w-])");
        if (self) parts.Add(@"\bThis PC\b");
        return parts.Count == 0 ? null : new Regex(string.Join("|", parts.Distinct()), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    public static Regex? For(Device d)
    {
        lock (d) return For(d.Ip?.ToString(), d.Mac, new[] { d.Hostname, d.Info.GetValueOrDefault("Computer name"), d.Info.GetValueOrDefault("NetBIOS name") }, d.IsSelf);
    }
}
