using System.Reflection;
using NetFinder.Core.Model;

namespace NetFinder.Ui;

internal static class Theme
{
    public static readonly Font Base = new("Segoe UI", 9f);
    public static readonly Font Bold = new("Segoe UI Semibold", 9f);
    public static readonly Font Title = new("Segoe UI Semibold", 15f);
    public static readonly Font Small = new("Segoe UI", 8.25f);

    public static readonly Color Accent = Color.FromArgb(0, 120, 212);
    public static readonly Color Brand = Color.FromArgb(18, 32, 58);
    public static readonly Color OtherSubnet = Color.FromArgb(255, 244, 229);
    public static readonly Color OtherSubnetText = Color.FromArgb(176, 84, 0);
    public static readonly Color Good = Color.FromArgb(16, 124, 16);
    public static readonly Color Muted = Color.FromArgb(96, 96, 96);
    public static readonly Color Panel = Color.FromArgb(246, 248, 250);

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
        TextRenderer.DrawText(g, hasGlyph ? glyph : "?", GlyphFontFor(r.Height, hasGlyph), r, Color.White, flags);
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

    private static System.Drawing.Drawing2D.GraphicsPath RoundedRect(Rectangle r, int radius)
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
