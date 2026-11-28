using PdfSharp;
using PdfSharp.Drawing;
using PdfSharp.Fonts;
using PdfSharp.Pdf;

namespace NetFinder.Core.Export;

/// <summary>
/// The device list as a PDF file (A4 landscape), made directly with PDFsharp: no browser or printer needed.
/// Keeps the columns people read; the Excel / CSV files have all of them.
/// </summary>
public static class PdfReport
{
    /// <summary>Text drawn as a picture: PNG bytes and its size in points.</summary>
    public readonly record struct Picture(byte[] Png, double Width, double Height);

    /// <summary>
    /// Set by the Windows app: draws Arabic / Hebrew text (joined letters, right to left) as a sharp picture,
    /// because the PDF library writes letters one by one. Without it such text is written as is.
    /// </summary>
    public static Func<string, double, bool, Picture?>? ComplexText { get; set; }

    private static readonly string[] Wanted =
    {
        "Type", "IP address", "Name", "Model", "Vendor", "MAC", "Serial number", "Windows", "CPU", "RAM", "Disk", "Open ports", "Risky ports", "Watch status",
    };

    private const double Margin = 28, PadX = 4, PadY = 3.2, BodySize = 7.2;
    private static readonly XColor Ink = XColor.FromArgb(0x16, 0x20, 0x2C), Muted = XColor.FromArgb(0x5B, 0x66, 0x75), Accent = XColor.FromArgb(0x1B, 0x64, 0xDA),
        Line = XColor.FromArgb(0xE3, 0xE8, 0xEF), Zebra = XColor.FromArgb(0xF7, 0xF9, 0xFC), Other = XColor.FromArgb(0xFF, 0xF4, 0xE5),
        Bad = XColor.FromArgb(0xB4, 0x23, 0x18), Good = XColor.FromArgb(0x14, 0x6C, 0x40), ChipBg = XColor.FromArgb(0xEE, 0xF4, 0xFB);

    /// <param name="columns">Column names; each row has one value per column.</param>
    public static void Save(string path, IReadOnlyList<string> columns, List<string[]> rows, string title)
    {
        EnsureFonts();
        using var doc = new PdfDocument();
        doc.Info.Title = title;
        doc.Info.Author = AppInfo.Company;
        doc.Info.Creator = $"{AppInfo.Name} {AppInfo.Version}";

        var body = Font(BodySize, false);
        var bold = Font(BodySize, true);
        var images = new List<XImage>();
        try
        {
            var w = new Writer(doc);
            var g = w.Gfx;
            var col = (string name) => IndexOf(columns, name);
            var show = Wanted.Select(col).Where(i => i >= 0 && (i <= 1 || rows.Any(r => r[i].Trim().Length > 0))).ToList();
            var netCol = col("Network");
            var riskyCol = col("Risky ports");
            var watchCol = col("Watch status");

            // ── title, counts and legend (first page only) ──
            var y = Margin;
            g.DrawString(title, Font(15, true), new XSolidBrush(Ink), Margin, y, XStringFormats.TopLeft);
            y += 22;
            var sub = $"{rows.Count} devices  ·  {DateTime.Now:yyyy-MM-dd HH:mm}  ·  {AppInfo.Name} {AppInfo.Version}  ·  © {AppInfo.Company}";
            g.DrawString(sub, Font(8, false), new XSolidBrush(Muted), Margin, y, XStringFormats.TopLeft);
            y += 16;
            var chips = rows.GroupBy(r => r[0]).OrderByDescending(x => x.Count()).Select(x => $"{x.Key}: {x.Count()}").ToList();
            if (riskyCol >= 0 && rows.Count(r => r[riskyCol].Length > 0) is var risky and > 0) chips.Add($"Risky ports: {risky}");
            if (watchCol >= 0 && rows.Count(r => r[watchCol].Length > 0) is var watched and > 0)
                chips.Add($"Watched: {watched}" + (rows.Count(r => r[watchCol].StartsWith("Down")) is var down and > 0 ? $" ({down} down)" : ""));
            var x0 = Margin;
            foreach (var c in chips)
            {
                var cw = g.MeasureString(c, body).Width + 14;
                if (x0 + cw > w.Width - Margin) { x0 = Margin; y += 17; }
                var bad = c.StartsWith("Risky") || c.Contains("down)");
                g.DrawRoundedRectangle(new XSolidBrush(bad ? XColor.FromArgb(0xFD, 0xEC, 0xEC) : ChipBg), x0, y, cw, 14, 12, 12);
                g.DrawString(c, bad ? bold : body, new XSolidBrush(bad ? Bad : Ink), new XRect(x0, y, cw, 14), XStringFormats.Center);
                x0 += cw + 5;
            }
            y += 20;
            var legend = new List<string>();
            if (netCol >= 0 && rows.Any(IsOther)) legend.Add("Orange rows are on another subnet or behind an NVR.");
            if (riskyCol >= 0 && rows.Any(r => r[riskyCol].Length > 0)) legend.Add("Risky ports (red): open NetFinder and select the device to see what to do.");
            if (legend.Count > 0)
            {
                g.DrawString(string.Join("  ", legend), Font(7.5, false), new XSolidBrush(Muted), Margin, y, XStringFormats.TopLeft);
                y += 14;
            }
            y += 2;

            // ── column widths: every column gets what it needs; the widest ones share what is left and wrap ──
            var avail = w.Width - 2 * Margin;
            var natural = new double[show.Count];
            var min = new double[show.Count];
            for (var k = 0; k < show.Count; k++)
            {
                var i = show[k];
                var head = g.MeasureString(columns[i], bold).Width;
                var widest = rows.Count == 0 ? 0 : rows.Max(r => g.MeasureString(r[i], body).Width);
                natural[k] = Math.Max(head, widest) + 2 * PadX;
                // keep words whole (model numbers, MACs) unless a word is really long
                var word = columns[i].Split(' ').Max(p => g.MeasureString(p, bold).Width);
                var longest = rows.Count == 0 ? 0 : rows.Max(r => r[i].Split(' ').Max(p => g.MeasureString(p, body).Width));
                min[k] = Math.Min(natural[k], Math.Max(34, Math.Max(word, Math.Min(longest, 95))) + 2 * PadX);
            }
            var widths = FitWidths(natural, min, avail);

            // ── table ──
            var lh = body.GetHeight();
            void Header()
            {
                var hh = show.Select((i, k) => Wrap(g, columns[i], bold, widths[k] - 2 * PadX).Count).Max() * lh + 2 * PadY + 1;
                g.DrawRectangle(new XSolidBrush(Accent), Margin, y, avail, hh);
                var x = Margin;
                for (var k = 0; k < show.Count; k++)
                {
                    var ly = y + PadY + 0.5;
                    foreach (var l in Wrap(g, columns[show[k]], bold, widths[k] - 2 * PadX))
                    {
                        g.DrawString(l, bold, XBrushes.White, x + PadX, ly, XStringFormats.TopLeft);
                        ly += lh;
                    }
                    x += widths[k];
                }
                y += hh;
            }
            Header();
            var pen = new XPen(Line, 0.6);
            var bottom = w.Height - Margin - 14;
            for (var n = 0; n < rows.Count; n++)
            {
                var r = rows[n];
                var cells = new List<(List<string> Lines, XImage? Pic, double PicW, double PicH)>();
                double rowH = 0;
                for (var k = 0; k < show.Count; k++)
                {
                    var text = r[show[k]];
                    var cw = widths[k] - 2 * PadX;
                    if (ComplexText != null && IsComplex(text) && ComplexText(text, BodySize, false) is { } pic)
                    {
                        var img = XImage.FromStream(new MemoryStream(pic.Png));
                        images.Add(img);
                        var scale = Math.Min(1, cw / pic.Width);
                        cells.Add((new List<string>(), img, pic.Width * scale, pic.Height * scale));
                        rowH = Math.Max(rowH, pic.Height * scale);
                    }
                    else
                    {
                        var lines = Wrap(g, text, StrongCell(show[k], text) ? bold : body, cw);
                        cells.Add((lines, null, 0, 0));
                        rowH = Math.Max(rowH, lines.Count * lh);
                    }
                }
                rowH += 2 * PadY;
                if (y + rowH > bottom)
                {
                    g = w.NewPage();
                    y = Margin;
                    Header();
                }
                var fill = IsOther(r) ? Other : n % 2 == 1 ? Zebra : XColors.White;
                if (fill != XColors.White) g.DrawRectangle(new XSolidBrush(fill), Margin, y, avail, rowH);
                var x = Margin;
                for (var k = 0; k < show.Count; k++)
                {
                    var (lines, pic, pw, ph) = cells[k];
                    if (pic != null)
                        g.DrawImage(pic, x + widths[k] - PadX - pw, y + PadY, pw, ph); // right to left: from the right edge
                    else
                    {
                        var i = show[k];
                        var text = r[i];
                        var color = i == riskyCol ? Bad : i == watchCol ? (text.StartsWith("Down") ? Bad : Good) : Ink;
                        var font = StrongCell(i, text) ? bold : body;
                        var ly = y + PadY;
                        foreach (var l in lines)
                        {
                            g.DrawString(l, font, new XSolidBrush(color), x + PadX, ly, XStringFormats.TopLeft);
                            ly += lh;
                        }
                    }
                    x += widths[k];
                }
                y += rowH;
                g.DrawLine(pen, Margin, y, Margin + avail, y);
            }
            if (rows.Count == 0)
                g.DrawString("No devices in the list.", body, new XSolidBrush(Muted), Margin + PadX, y + PadY + 2, XStringFormats.TopLeft);
            w.Finish();

            // ── footer on every page ──
            var foot = Font(7, false);
            for (var p = 0; p < doc.PageCount; p++)
            {
                using var fg = XGraphics.FromPdfPage(doc.Pages[p], XGraphicsPdfPageOptions.Append);
                var fy = doc.Pages[p].Height.Point - Margin + 2;
                fg.DrawString($"{AppInfo.Name} · {AppInfo.Company}", foot, new XSolidBrush(Muted), Margin, fy, XStringFormats.TopLeft);
                fg.DrawString($"Page {p + 1} of {doc.PageCount}", foot, new XSolidBrush(Muted), doc.Pages[p].Width.Point - Margin, fy, XStringFormats.TopRight);
            }
            doc.Save(path);
        }
        finally
        {
            foreach (var i in images) i.Dispose();
        }

        bool IsOther(string[] r) => IndexOf(columns, "Network") is var nc and >= 0 && (r[nc].StartsWith("Other") || r[nc].StartsWith("Behind NVR"));
        bool StrongCell(int i, string text) => columns[i] is "Risky ports" || (columns[i] == "Watch status" && text.StartsWith("Down"));
    }

    private static int IndexOf(IReadOnlyList<string> columns, string name)
    {
        for (var i = 0; i < columns.Count; i++) if (columns[i] == name) return i;
        return -1;
    }

    /// <summary>
    /// Columns that fit keep their width; the wider ones are capped at the same width so the total fits (they wrap).
    /// When everything fits, all grow to fill the page.
    /// </summary>
    internal static double[] FitWidths(double[] natural, double[] min, double avail)
    {
        double Total(double cap) => natural.Select((n, k) => Math.Min(n, Math.Max(cap, min[k]))).Sum();
        double[] With(double cap) => natural.Select((n, k) => Math.Min(n, Math.Max(cap, min[k]))).ToArray();
        if (natural.Length == 0) return natural;
        if (natural.Sum() <= avail)
        {
            var grow = avail / natural.Sum();
            return natural.Select(n => n * grow).ToArray();
        }
        double lo = 0, hi = natural.Max();
        for (var i = 0; i < 40; i++)
        {
            var mid = (lo + hi) / 2;
            if (Total(mid) <= avail) lo = mid; else hi = mid;
        }
        var w = With(lo);
        var sum = w.Sum();
        if (sum > avail) return w.Select(x => x * avail / sum).ToArray(); // even the minimums do not fit
        // hand out what is left to the capped columns
        var capped = Enumerable.Range(0, w.Length).Where(k => w[k] < natural[k]).ToList();
        if (capped.Count > 0) foreach (var k in capped) w[k] += (avail - sum) / capped.Count;
        return w;
    }

    /// <summary>Breaks text into lines that fit the width (long words are cut).</summary>
    internal static List<string> Wrap(XGraphics g, string text, XFont font, double width)
    {
        var lines = new List<string>();
        foreach (var para in text.Replace("\r", "").Split('\n'))
        {
            var line = "";
            foreach (var word in para.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                var tryLine = line.Length == 0 ? word : line + " " + word;
                if (g.MeasureString(tryLine, font).Width <= width) { line = tryLine; continue; }
                if (line.Length > 0) lines.Add(line);
                line = word;
                while (line.Length > 1 && g.MeasureString(line, font).Width > width)
                {
                    var cut = line.Length - 1;
                    while (cut > 1 && g.MeasureString(line[..cut], font).Width > width) cut--;
                    lines.Add(line[..cut]);
                    line = line[cut..];
                }
            }
            lines.Add(line);
        }
        while (lines.Count > 1 && lines[^1].Length == 0) lines.RemoveAt(lines.Count - 1);
        return lines;
    }

    /// <summary>Arabic, Hebrew and other right-to-left scripts.</summary>
    public static bool IsComplex(string s) => s.Any(c => c is >= '\u0590' and <= '\u08FF' or >= '\uFB1D' and <= '\uFDFF' or >= '\uFE70' and <= '\uFEFF');

    private static XFont Font(double size, bool bold) =>
        new(FontFiles.Family, size, bold ? XFontStyleEx.Bold : XFontStyleEx.Regular, new XPdfFontOptions(PdfFontEncoding.Unicode));

    /// <summary>Pages are made as the table needs them.</summary>
    private sealed class Writer
    {
        private readonly PdfDocument _doc;
        public XGraphics Gfx { get; private set; } = null!;
        public double Width, Height;
        public Writer(PdfDocument doc) { _doc = doc; NewPage(); }

        public XGraphics NewPage()
        {
            Gfx?.Dispose();
            var page = _doc.AddPage();
            page.Size = PageSize.A4;
            page.Orientation = PageOrientation.Landscape;
            Width = page.Width.Point;
            Height = page.Height.Point;
            return Gfx = XGraphics.FromPdfPage(page);
        }

        public void Finish() => Gfx.Dispose();
    }

    private static readonly object FontGate = new();
    private static bool _fontsSet;

    private static void EnsureFonts()
    {
        lock (FontGate)
        {
            if (_fontsSet) return;
            if (GlobalFontSettings.FontResolver == null) GlobalFontSettings.FontResolver = new FontFiles();
            _fontsSet = true;
        }
    }

    /// <summary>Segoe UI from Windows (Arial if missing); DejaVu / Liberation on Linux (tests).</summary>
    private sealed class FontFiles : IFontResolver
    {
        public const string Family = "NetFinder Sans";

        private static readonly string WinFonts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows) is { Length: > 0 } w ? w : @"C:\Windows", "Fonts");
        private static readonly string[] Regular =
        {
            Path.Combine(WinFonts, "segoeui.ttf"), Path.Combine(WinFonts, "arial.ttf"),
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        };
        private static readonly string[] Bold =
        {
            Path.Combine(WinFonts, "seguisb.ttf"), Path.Combine(WinFonts, "segoeuib.ttf"), Path.Combine(WinFonts, "arialbd.ttf"),
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        };

        public FontResolverInfo? ResolveTypeface(string familyName, bool isBold, bool isItalic) =>
            new(isBold ? "nf-bold" : "nf-regular");

        public byte[]? GetFont(string faceName)
        {
            var list = faceName == "nf-bold" ? Bold.Concat(Regular) : Regular;
            foreach (var f in list)
                if (File.Exists(f)) return File.ReadAllBytes(f);
            return null;
        }
    }
}
