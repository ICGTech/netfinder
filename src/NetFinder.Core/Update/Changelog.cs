using System.Reflection;

namespace NetFinder.Core.Update;

/// <summary>Short "what's new" notes per version, read from CHANGELOG.md (embedded in the program).</summary>
public static class Changelog
{
    private static readonly Lazy<List<(string Version, List<string> Items)>> Entries = new(() => Parse(Read()));

    public static IReadOnlyList<(string Version, List<string> Items)> All => Entries.Value;

    /// <summary>Versions newer than <paramref name="lastVersion"/> up to the running one, newest first (at most 3).</summary>
    public static List<(string Version, List<string> Items)> Since(string? lastVersion) =>
        All.Where(e => !UpdateChecker.IsNewer(e.Version, AppInfo.Version) &&
                       (lastVersion == null ? e.Version == AppInfo.Version : UpdateChecker.IsNewer(e.Version, lastVersion)))
           .Take(3).ToList();

    /// <summary>"What's new" text for a message box.</summary>
    public static string Text(IEnumerable<(string Version, List<string> Items)> entries)
    {
        var list = entries.ToList();
        if (list.Count == 0) return "";
        if (list.Count == 1) return string.Join("\n", list[0].Items.Take(6).Select(i => "•  " + i));
        return string.Join("\n\n", list.Select(e => $"Version {e.Version}:\n" + string.Join("\n", e.Items.Take(4).Select(i => "•  " + i))));
    }

    /// <summary>One short line from release notes (the "- " lines), for the update bar.</summary>
    public static string OneLine(string? notes, int maxLength = 110)
    {
        if (string.IsNullOrWhiteSpace(notes)) return "";
        var items = notes.Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith("- ") || l.StartsWith("* ") || l.StartsWith("• "))
            .Select(l => l[2..].Trim()).Where(l => l.Length > 0 && !l.Contains("Full Changelog", StringComparison.OrdinalIgnoreCase) && !l.Contains(" by @"))
            .ToList();
        var line = string.Join("  ·  ", items);
        return line.Length <= maxLength ? line : line[..(maxLength - 1)].TrimEnd() + "…";
    }

    internal static List<(string Version, List<string> Items)> Parse(string text)
    {
        var res = new List<(string, List<string>)>();
        List<string>? cur = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("## "))
            {
                var v = line[3..].Trim().TrimStart('v', 'V');
                cur = new List<string>();
                res.Add((v, cur));
            }
            else if (cur != null && line.StartsWith("- ")) cur.Add(line[2..].Trim());
        }
        return res;
    }

    private static string Read()
    {
        try
        {
            using var s = typeof(Changelog).Assembly.GetManifestResourceStream("CHANGELOG.md");
            if (s == null) return "";
            using var r = new StreamReader(s);
            return r.ReadToEnd();
        }
        catch { return ""; }
    }
}
