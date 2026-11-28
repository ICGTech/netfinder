using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;

namespace NetFinder.Core.Text;

/// <summary>
/// The language of the window. Every text is written in English in the code and passed through <see cref="T(string)"/>;
/// the translations live in Lang/&lt;code&gt;.json (English text → translated text), built into the program.
/// Texts with values use the same English text with {0}, {1}…: <c>T($"{n} devices")</c> looks up "{0} devices".
/// A missing translation simply shows the English text. More languages: drop a &lt;code&gt;.json in a "lang" folder next to NetFinder.exe.
/// </summary>
public static class L
{
    public sealed record Language(string Code, string Name, string EnglishName, bool Rtl);

    /// <summary>The built-in languages, each named in its own language.</summary>
    public static readonly IReadOnlyList<Language> Builtin = new Language[]
    {
        new("en", "English", "English", false),
        new("ar", "العربية", "Arabic", true),
        new("fr", "Français", "French", false),
        new("es", "Español", "Spanish", false),
        new("pt", "Português", "Portuguese", false),
        new("ur", "اردو", "Urdu", true),
        new("hi", "हिन्दी", "Hindi", false),
        new("zh", "中文（简体）", "Chinese (Simplified)", false),
    };

    public static Language Current { get; private set; } = Builtin[0];
    public static bool Rtl => Current.Rtl;
    private static Dictionary<string, string> _map = new();

    /// <summary>Built-in languages plus any lang\xx.json next to the program.</summary>
    public static List<Language> Available()
    {
        var list = Builtin.ToList();
        try
        {
            var dir = Path.Combine(AppContext.BaseDirectory, "lang");
            if (Directory.Exists(dir))
                foreach (var f in Directory.GetFiles(dir, "*.json"))
                {
                    var code = Path.GetFileNameWithoutExtension(f).ToLowerInvariant();
                    if (list.Any(l => l.Code == code)) continue;
                    var m = Read(File.ReadAllText(f));
                    list.Add(new Language(code, m.GetValueOrDefault("_name") ?? code, m.GetValueOrDefault("_name") ?? code, m.GetValueOrDefault("_rtl") == "true"));
                }
        }
        catch { }
        return list;
    }

    /// <summary>Switches the language (call before the window is built). Unknown codes fall back to English.</summary>
    public static void Use(string? code)
    {
        code = (code ?? "en").Trim().ToLowerInvariant();
        var lang = Available().FirstOrDefault(l => l.Code == code) ?? Builtin[0];
        var map = new Dictionary<string, string>();
        if (lang.Code != "en")
        {
            using (var s = typeof(L).Assembly.GetManifestResourceStream($"NetFinder.Core.Lang.{lang.Code}.json"))
                if (s != null) foreach (var kv in Read(new StreamReader(s, Encoding.UTF8).ReadToEnd())) map[kv.Key] = kv.Value;
            // a file next to the program adds to / corrects the built-in one
            try
            {
                var f = Path.Combine(AppContext.BaseDirectory, "lang", lang.Code + ".json");
                if (File.Exists(f)) foreach (var kv in Read(File.ReadAllText(f, Encoding.UTF8))) map[kv.Key] = kv.Value;
            }
            catch { }
        }
        _map = map;
        Current = lang;
    }

    /// <summary>Uses another language until disposed (to say one sentence in the language about to be used).</summary>
    public static IDisposable Scope(string code)
    {
        var (map, cur) = (_map, Current);
        Use(code);
        return new Restore(() => { _map = map; Current = cur; });
    }

    private sealed class Restore : IDisposable
    {
        private Action? _a;
        public Restore(Action a) => _a = a;
        public void Dispose() { _a?.Invoke(); _a = null; }
    }

    /// <summary>All translations of a language (for the self-test).</summary>
    public static Dictionary<string, string> Table(string code)
    {
        using var s = typeof(L).Assembly.GetManifestResourceStream($"NetFinder.Core.Lang.{code}.json");
        return s == null ? new() : Read(new StreamReader(s, Encoding.UTF8).ReadToEnd());
    }

    private static Dictionary<string, string> Read(string json)
    {
        var d = JsonSerializer.Deserialize<Dictionary<string, string>>(json, new JsonSerializerOptions { ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        return d ?? new();
    }

    /// <summary>The text in the current language (the English text when there is no translation).</summary>
    public static string T(string? english)
    {
        if (string.IsNullOrEmpty(english)) return english ?? "";
        if (_map.TryGetValue(english, out var t) && t.Length > 0) return RtlStart(t);
        // a table cell in Arabic / Urdu carries invisible left-to-right marks around English text (see Bidi)
        if (english[0] == '\u200E' && english.Trim('\u200E') is var bare && _map.TryGetValue(bare, out t) && t.Length > 0) return RtlStart(t);
        Miss(english.Trim('\u200E'));
        return english;
    }

    /// <summary>English texts asked for that have no translation in the current language (for the screenshot check).</summary>
    public static readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> Missing = new();

    private static void Miss(string key)
    {
        if (Current.Code != "en" && Missing.Count < 2000 && key.Any(char.IsLetter)) Missing.AddOrUpdate(key, 1, (_, n) => n + 1);
    }

    /// <summary>A text with values: <c>T($"{n} of {m} ports up")</c> looks up "{0} of {1} ports up" and puts the values in.</summary>
    public static string T(ref TextWithValues text)
    {
        var key = text.Template;
        var args = text.Args;
        string t;
        if (_map.TryGetValue(key, out var x) && x.Length > 0) t = x;
        else { t = key; Miss(key); }
        // in Arabic / Urdu an English value (a name, a model, "SW-1 (10.0.0.2)") keeps its own left-to-right order inside the sentence
        if (Rtl) for (var i = 0; i < args.Length; i++) args[i] = new LtrValue(args[i]);
        try { return RtlStart(string.Format(CultureInfo.InvariantCulture, t, args)); }
        catch (FormatException) { return string.Format(CultureInfo.InvariantCulture, key, args); }
    }

    /// <summary>
    /// An Arabic / Urdu sentence that starts with an English word ("ping صغير…", "CORE-SW1 · منفذ 15") gets an invisible right-to-left
    /// mark in front, so Windows reads the whole line right to left instead of guessing left to right from its first word.
    /// </summary>
    private static string RtlStart(string s)
    {
        if (!Rtl || s.Length == 0 || s[0] == '\u200F') return s;
        foreach (var ch in s)
        {
            if (ch is >= '\u0590' and <= '\u08FF' or >= '\uFB1D' and <= '\uFEFC') return s; // starts right to left already
            if (ch == '\u200E' || char.IsLetter(ch)) return HasRtlLetters(s) ? "\u200F" + s : s;
        }
        return s;
    }

    /// <summary>True when the text has Arabic, Urdu or Hebrew letters.</summary>
    public static bool HasRtlLetters(string? s)
    {
        if (s == null) return false;
        foreach (var ch in s) if (ch is >= '\u0590' and <= '\u08FF' or >= '\uFB1D' and <= '\uFEFC') return true;
        return false;
    }

    /// <summary>
    /// In an Arabic / Urdu window: English text with letters gets an invisible left-to-right mark at both ends, so "HP LaserJet (M404)"
    /// does not show as "(HP LaserJet (M404". Other text, and every text in left-to-right languages, is returned as it is.
    /// </summary>
    public static string Bidi(string? s)
    {
        if (string.IsNullOrEmpty(s)) return s ?? "";
        if (!Rtl || s[0] == '\u200E' || HasRtlLetters(s) || !s.Any(char.IsLetter)) return s;
        return "\u200E" + s + "\u200E";
    }

    private sealed class LtrValue : IFormattable
    {
        private readonly object? _v;
        public LtrValue(object? v) => _v = v;
        public string ToString(string? format, IFormatProvider? p) => Bidi(_v is IFormattable f ? f.ToString(format, p) : _v?.ToString());
        public override string ToString() => ToString(null, CultureInfo.InvariantCulture);
    }

    /// <summary>Builds "{0} of {1} ports up" + the values from an interpolated string.</summary>
    [InterpolatedStringHandler]
    public ref struct TextWithValues
    {
        private readonly StringBuilder _template;
        private readonly List<object?> _args;

        public TextWithValues(int literalLength, int formattedCount)
        {
            _template = new StringBuilder(literalLength + formattedCount * 4);
            _args = new List<object?>(formattedCount);
        }

        public void AppendLiteral(string s) => _template.Append(s.Replace("{", "{{").Replace("}", "}}"));
        public void AppendFormatted<TValue>(TValue value) => Add(value, 0, null);
        public void AppendFormatted<TValue>(TValue value, string? format) => Add(value, 0, format);
        public void AppendFormatted<TValue>(TValue value, int alignment) => Add(value, alignment, null);
        public void AppendFormatted<TValue>(TValue value, int alignment, string? format) => Add(value, alignment, format);
        public void AppendFormatted(string? value) => Add(value, 0, null);

        private void Add(object? value, int alignment, string? format)
        {
            _template.Append('{').Append(_args.Count);
            if (alignment != 0) _template.Append(',').Append(alignment);
            if (format != null) _template.Append(':').Append(format);
            _template.Append('}');
            _args.Add(value);
        }

        public string Template => _template.ToString();
        public object?[] Args => _args.ToArray();
    }
}
