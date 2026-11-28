using System.Reflection;
using NetFinder.Core.Model;
using static NetFinder.Core.Text.L;

namespace NetFinder.Ui;

internal static class Theme
{
    /// <summary>Test only: NETFINDER_TEXT_SCALE=1.5 makes every font bigger, to check that no text gets cut.</summary>
    private static readonly float K =
        float.TryParse(Environment.GetEnvironmentVariable("NETFINDER_TEXT_SCALE"), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var k) && k is > 0.5f and < 4f ? k : 1f;

    public static readonly Font Base = new("Segoe UI", 9f * K);
    public static readonly Font Bold = new("Segoe UI Semibold", 9f * K);
    public static readonly Font Title = new("Segoe UI Semibold", 15f * K);
    public static readonly Font Small = new("Segoe UI", 8.25f * K);

    public static readonly Color Accent = Color.FromArgb(0, 120, 212);
    public static readonly Color Brand = Color.FromArgb(18, 32, 58);
    public static readonly Color OtherSubnet = Color.FromArgb(255, 244, 229);
    public static readonly Color OtherSubnetText = Color.FromArgb(176, 84, 0);
    public static readonly Color Good = Color.FromArgb(16, 124, 16);
    public static readonly Color Muted = Color.FromArgb(96, 96, 96);
    public static readonly Color Panel = Color.FromArgb(246, 248, 250);

    // ── main window palette (light / dark). Dialogs keep the light colors above. ──
    public static readonly Palette LightPalette = new(false,
        Bg: Hex("F5F7FA"), Surface: Hex("FFFFFF"), Surface2: Hex("F8FAFC"), Border: Hex("E3E8EF"), Text: Hex("16202C"), Muted: Hex("5B6675"),
        Accent: Hex("1B64DA"), AccentText: Hex("FFFFFF"), AccentSoft: Hex("E8F0FD"), AccentSoftText: Hex("124AA6"),
        RowSelected: Hex("EEF4FE"), Hover: Hex("F2F5F9"), Good: Hex("146C40"), GoodSoft: Hex("E7F5EE"), Warn: Hex("8A4B00"), WarnSoft: Hex("FDF1E3"),
        OtherRow: Hex("FFF8EE"), InputBg: Hex("FFFFFF"), Link: Hex("1B64DA"), Bar: Hex("E3E8EF"), Bad: Hex("B42318"), BadSoft: Hex("FDECEC"));

    public static readonly Palette DarkPalette = new(true,
        Bg: Hex("0E151D"), Surface: Hex("16212C"), Surface2: Hex("131C26"), Border: Hex("243242"), Text: Hex("E6EDF3"), Muted: Hex("9AA7B4"),
        Accent: Hex("4C9AFF"), AccentText: Hex("0B1622"), AccentSoft: Hex("1A2940"), AccentSoftText: Hex("9CC7FF"),
        RowSelected: Hex("1A2940"), Hover: Hex("1B2733"), Good: Hex("8FD3AE"), GoodSoft: Hex("173A2A"), Warn: Hex("F4BF75"), WarnSoft: Hex("3A2A14"),
        OtherRow: Hex("241F17"), InputBg: Hex("0F1821"), Link: Hex("6CB0FF"), Bar: Hex("243242"), Bad: Hex("FF9C94"), BadSoft: Hex("3D1D1D"));

    /// <summary>The palette of the main window now.</summary>
    public static Palette P { get; private set; } = LightPalette;
    public static void SetDark(bool dark) => P = dark ? DarkPalette : LightPalette;

    public static Color Hex(string h) => Color.FromArgb(Convert.ToInt32(h[..2], 16), Convert.ToInt32(h[2..4], 16), Convert.ToInt32(h[4..6], 16));

    /// <summary>a blended toward b (t = 0 → a, 1 → b).</summary>
    public static Color Mix(Color a, Color b, double t) =>
        Color.FromArgb((int)Math.Round(a.R + (b.R - a.R) * t), (int)Math.Round(a.G + (b.G - a.G) * t), (int)Math.Round(a.B + (b.B - a.B) * t));

    public static readonly Font Heading = new("Segoe UI Semibold", 14f * K);
    public static readonly Font Section = new("Segoe UI Semibold", 7.75f * K);
    public static readonly Font Big = new("Segoe UI Semibold", 12f * K);
    public static readonly Font Header = new("Segoe UI", 9.75f * K);
    public static readonly Font HeaderBold = new("Segoe UI Semibold", 9.75f * K);
    public static readonly Font Mono = MonoFont(9.75f, FontStyle.Regular);
    public static readonly Font MonoTitle = MonoFont(15f, FontStyle.Bold);

    private static Font MonoFont(float size, FontStyle style)
    {
        size *= K;
        var f = new Font("Cascadia Mono", size, style);
        if (f.Name == "Cascadia Mono") return f;
        f.Dispose();
        return new Font("Consolas", size, style);
    }

    /// <summary>The color of a type's symbol on the tinted tile (lighter in dark mode so it stays readable).</summary>
    public static Color TypeInk(string type) => P.Dark ? Mix(ForType(type), Color.White, 0.42) : ForType(type);

    /// <summary>New-look type icon: a softly tinted rounded tile with the symbol in the type color.</summary>
    public static void DrawTypeTile(Graphics g, Rectangle r, string type, Color background)
    {
        var smooth = g.SmoothingMode;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using (var path = RoundedRect(r, Math.Max(3, r.Width / 4)))
        using (var b = new SolidBrush(Mix(background, ForType(type), P.Dark ? 0.24 : 0.12)))
            g.FillPath(b, path);
        g.SmoothingMode = smooth;
        var flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine | TextFormatFlags.NoClipping;
        var hasGlyph = TypeGlyphs.TryGetValue(type, out var glyph);
        Ui.DrawText(g, hasGlyph ? glyph : "?", GlyphFontFor((int)(r.Height * 0.86 * GlyphScale(type)), hasGlyph), r, TypeInk(type), flags);
    }

    private static readonly Dictionary<string, Color> TypeColors = new()
    {
        [DeviceTypes.Router] = Color.FromArgb(0, 120, 212),
        [DeviceTypes.Switch] = Color.FromArgb(0, 99, 177),
        [DeviceTypes.AccessPoint] = Color.FromArgb(0, 153, 188),
        [DeviceTypes.Firewall] = Color.FromArgb(196, 43, 28),
        [DeviceTypes.Printer] = Color.FromArgb(135, 100, 184),
        [DeviceTypes.Camera] = Color.FromArgb(202, 80, 16),
        [DeviceTypes.Nvr] = Color.FromArgb(160, 60, 10),
        [DeviceTypes.Tv] = Color.FromArgb(194, 57, 179),
        [DeviceTypes.Android] = Color.FromArgb(16, 137, 62),
        [DeviceTypes.IPhone] = Color.FromArgb(70, 70, 70),
        [DeviceTypes.Mac] = Color.FromArgb(90, 90, 90),
        [DeviceTypes.WindowsPc] = Color.FromArgb(0, 90, 158),
        [DeviceTypes.WindowsServer] = Color.FromArgb(0, 70, 120),
        [DeviceTypes.Linux] = Color.FromArgb(200, 140, 0),
        [DeviceTypes.Nas] = Color.FromArgb(73, 130, 5),
        [DeviceTypes.Iot] = Color.FromArgb(0, 128, 128),
        [DeviceTypes.VoipPhone] = Color.FromArgb(107, 105, 214),
        [DeviceTypes.Console] = Color.FromArgb(16, 124, 16),
        [DeviceTypes.Vm] = Color.FromArgb(120, 120, 160),
        [DeviceTypes.Phone] = Color.FromArgb(60, 150, 90),
        [DeviceTypes.Ups] = Color.FromArgb(150, 110, 40),
        [DeviceTypes.AccessControl] = Color.FromArgb(150, 60, 100),
    };

    public static Color ForType(string type) => type == ThisPc ? Brand : TypeColors.TryGetValue(type, out var c) ? c : Color.FromArgb(150, 150, 150);

    public const string ThisPc = "This PC";

    // Symbol drawn (in white) inside the colored square of each type. Segoe UI Emoji / Symbol ship with Windows 10/11
    // and GDI draws them as one-color outlines, so they take the text color.
    private static readonly Dictionary<string, string> TypeGlyphs = new()
    {
        [DeviceTypes.Router] = "\U0001F310",       // globe
        [DeviceTypes.Switch] = "\U0001F500",       // crossed arrows
        [DeviceTypes.AccessPoint] = "\U0001F4F6",  // signal bars
        [DeviceTypes.Firewall] = "\U0001F6E1",     // shield
        [DeviceTypes.Printer] = "\U0001F5A8",      // printer
        [DeviceTypes.Camera] = "\U0001F4F7",       // camera
        [DeviceTypes.Nvr] = "\U0001F4FC",          // video cassette
        [DeviceTypes.Tv] = "\U0001F4FA",           // television
        [DeviceTypes.Android] = "\U0001F4F1",      // mobile phone
        [DeviceTypes.IPhone] = "\U0001F4F1",
        [DeviceTypes.Phone] = "\U0001F4F1",
        [DeviceTypes.Mac] = "\U0001F4BB",          // laptop
        [DeviceTypes.WindowsPc] = "\U0001F5A5",    // desktop computer
        [DeviceTypes.WindowsServer] = "\U0001F5A7",// three networked computers
        [DeviceTypes.Linux] = "\U0001F427",        // penguin
        [DeviceTypes.Nas] = "\U0001F5C4",          // file cabinet
        [DeviceTypes.Iot] = "\U0001F4A1",          // light bulb
        [DeviceTypes.VoipPhone] = "\u260E",        // telephone
        [DeviceTypes.Console] = "\U0001F3AE",      // game controller
        [DeviceTypes.Vm] = "\U0001F4E6",           // package
        [DeviceTypes.Ups] = "\U0001F50B",          // battery
        [DeviceTypes.AccessControl] = "\U0001F510",// lock with key
        [ThisPc] = "\U0001F3E0",                   // house
    };

    /// <summary>The server symbol (not an emoji: Windows draws it from Segoe UI Symbol) is drawn small; make it as big as the others.</summary>
    private static float GlyphScale(string type) => type == DeviceTypes.WindowsServer ? 1.45f : 1f;

    private static readonly Dictionary<(int, bool), Font> GlyphFonts = new();

    /// <summary>Font sized in pixels for an icon of that height (so it fits at any Windows scaling).</summary>
    private static Font GlyphFontFor(int height, bool emoji)
    {
        lock (GlyphFonts)
        {
            if (!GlyphFonts.TryGetValue((height, emoji), out var f))
                GlyphFonts[(height, emoji)] = f = emoji
                    ? new Font("Segoe UI Emoji", Math.Max(6f, height * 0.58f), GraphicsUnit.Pixel)
                    : new Font("Segoe UI Semibold", Math.Max(6f, height * 0.7f), GraphicsUnit.Pixel);
            return f;
        }
    }

    /// <summary>Draws the type icon: a rounded square in the type color with a white symbol.</summary>
    public static void DrawTypeIcon(Graphics g, Rectangle r, string type)
    {
        var smooth = g.SmoothingMode;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using (var path = RoundedRect(r, Math.Max(3, r.Width / 5)))
        using (var b = new SolidBrush(ForType(type)))
            g.FillPath(b, path);
        g.SmoothingMode = smooth;
        var flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine | TextFormatFlags.NoClipping;
        var hasGlyph = TypeGlyphs.TryGetValue(type, out var glyph);
        Ui.DrawText(g, hasGlyph ? glyph : "?", GlyphFontFor((int)(r.Height * GlyphScale(type)), hasGlyph), r, Color.White, flags);
    }

    /// <summary>The type icon as a picture (device tab header, menus), on an opaque background.</summary>
    public static Bitmap TypeIcon(string type, int size, Color? background = null)
    {
        // 32bppRgb (no alpha): GDI text on an alpha bitmap punches transparent holes.
        var bmp = new Bitmap(size, size, System.Drawing.Imaging.PixelFormat.Format32bppRgb);
        using var g = Graphics.FromImage(bmp);
        g.Clear(background ?? Color.White);
        DrawTypeIcon(g, new Rectangle(0, 0, size, size), type);
        return bmp;
    }

    public static System.Drawing.Drawing2D.GraphicsPath RoundedRect(Rectangle r, int radius)
    {
        var d = radius * 2;
        var p = new System.Drawing.Drawing2D.GraphicsPath();
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d - 1, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d - 1, r.Bottom - d - 1, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d - 1, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    public static Image? Logo()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("logo.png");
        return s == null ? null : Image.FromStream(new MemoryStream(ReadAll(s)));
    }

    public static Icon? AppIcon()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico");
        return s == null ? null : new Icon(new MemoryStream(ReadAll(s)));
    }

    private static byte[] ReadAll(Stream s) { using var m = new MemoryStream(); s.CopyTo(m); return m.ToArray(); }
}

/// <summary>The colors of the main window in one theme.</summary>
internal sealed record Palette(bool Dark, Color Bg, Color Surface, Color Surface2, Color Border, Color Text, Color Muted,
    Color Accent, Color AccentText, Color AccentSoft, Color AccentSoftText, Color RowSelected, Color Hover,
    Color Good, Color GoodSoft, Color Warn, Color WarnSoft, Color OtherRow, Color InputBg, Color Link, Color Bar, Color Bad, Color BadSoft);
