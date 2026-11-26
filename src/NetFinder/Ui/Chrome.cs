using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using NetFinder.Core;

namespace NetFinder.Ui;

// The painted parts of the main window (1.1.12 look): header, side menu, tabs, buttons, cards and tables.
// Every color comes from Theme.P, so switching light / dark is a repaint.

internal static class Ui
{
    public static int S(Control c, int px) => c.LogicalToDeviceUnits(px);

    public static void FillRound(Graphics g, Rectangle r, int radius, Color fill, Color? border = null)
    {
        if (r.Width <= 1 || r.Height <= 1) return;
        var smooth = g.SmoothingMode;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        radius = Math.Max(1, Math.Min(radius, Math.Min(r.Width, r.Height) / 2));
        using (var path = Theme.RoundedRect(r, radius))
        {
            using (var b = new SolidBrush(fill)) g.FillPath(b, path);
            if (border is { } bc) using (var p = new Pen(bc)) g.DrawPath(p, path);
        }
        g.SmoothingMode = smooth;
    }

    public const TextFormatFlags Line = TextFormatFlags.NoPadding | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.VerticalCenter;
    public const TextFormatFlags Wrap = TextFormatFlags.NoPadding | TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl;

    public static int WrapHeight(string text, Font f, int width) =>
        text.Length == 0 ? 0 : TextRenderer.MeasureText(text, f, new Size(Math.Max(10, width), int.MaxValue), Wrap).Height;

    /// <summary>A control painted by us, double-buffered.</summary>
    public static void Painted(Control c) =>
        typeof(Control).GetMethod("SetStyle", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .Invoke(c, new object[] { ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true });
}

/// <summary>Toolbar, menu and status bar colors.</summary>
internal sealed class PaletteColors : ProfessionalColorTable
{
    private static Palette P => Theme.P;
    public PaletteColors() { UseSystemColors = false; }
    public override Color ToolStripGradientBegin => P.Surface;
    public override Color ToolStripGradientMiddle => P.Surface;
    public override Color ToolStripGradientEnd => P.Surface;
    public override Color ToolStripBorder => P.Border;
    public override Color ToolStripDropDownBackground => P.Surface;
    public override Color ImageMarginGradientBegin => P.Surface;
    public override Color ImageMarginGradientMiddle => P.Surface;
    public override Color ImageMarginGradientEnd => P.Surface;
    public override Color MenuBorder => P.Border;
    public override Color MenuItemBorder => P.Hover;
    public override Color MenuItemSelected => P.Hover;
    public override Color MenuItemSelectedGradientBegin => P.Hover;
    public override Color MenuItemSelectedGradientEnd => P.Hover;
    public override Color MenuItemPressedGradientBegin => P.Hover;
    public override Color MenuItemPressedGradientMiddle => P.Hover;
    public override Color MenuItemPressedGradientEnd => P.Hover;
    public override Color SeparatorDark => P.Border;
    public override Color SeparatorLight => P.Border;
    public override Color StatusStripGradientBegin => P.Surface;
    public override Color StatusStripGradientEnd => P.Surface;
    public override Color CheckBackground => P.AccentSoft;
    public override Color CheckSelectedBackground => P.AccentSoft;
    public override Color CheckPressedBackground => P.AccentSoft;
    public override Color ButtonSelectedHighlight => P.Hover;
    public override Color ButtonSelectedGradientBegin => P.Hover;
    public override Color ButtonSelectedGradientMiddle => P.Hover;
    public override Color ButtonSelectedGradientEnd => P.Hover;
    public override Color ButtonPressedGradientBegin => P.Hover;
    public override Color ButtonPressedGradientMiddle => P.Hover;
    public override Color ButtonPressedGradientEnd => P.Hover;
    public override Color OverflowButtonGradientBegin => P.Surface;
    public override Color OverflowButtonGradientMiddle => P.Surface;
    public override Color OverflowButtonGradientEnd => P.Surface;
}

/// <summary>
/// Paints the header (rounded outline buttons; Tag "primary" = filled accent, Tag "pill" = the green Listening pill),
/// the menus and the status bar.
/// </summary>
internal sealed class ChromeRenderer : ToolStripProfessionalRenderer
{
    private static Palette P => Theme.P;
    public ChromeRenderer() : base(new PaletteColors()) { RoundedEdges = false; }

    protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
    {
        using var b = new SolidBrush(P.Surface);
        e.Graphics.FillRectangle(b, e.AffectedBounds);
    }

    protected override void OnRenderImageMargin(ToolStripRenderEventArgs e)
    {
        using var b = new SolidBrush(P.Surface);
        e.Graphics.FillRectangle(b, e.AffectedBounds);
    }

    protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
    {
        using var pen = new Pen(P.Border);
        var r = e.ToolStrip.ClientRectangle;
        if (e.ToolStrip is ToolStripDropDown) e.Graphics.DrawRectangle(pen, 0, 0, r.Width - 1, r.Height - 1);
        else if (e.ToolStrip is StatusStrip) e.Graphics.DrawLine(pen, 0, 0, r.Width, 0);
        else e.Graphics.DrawLine(pen, 0, r.Height - 1, r.Width, r.Height - 1);
    }

    protected override void OnRenderButtonBackground(ToolStripItemRenderEventArgs e)
    {
        if (e.ToolStrip is ToolStripDropDown || e.ToolStrip is StatusStrip) { base.OnRenderButtonBackground(e); return; }
        DrawButton(e.Graphics, e.Item);
    }

    protected override void OnRenderDropDownButtonBackground(ToolStripItemRenderEventArgs e)
    {
        if (e.ToolStrip is ToolStripDropDown) { base.OnRenderDropDownButtonBackground(e); return; }
        DrawButton(e.Graphics, e.Item);
    }

    private static void DrawButton(Graphics g, ToolStripItem item)
    {
        var kind = item.Tag as string;
        var hot = item.Enabled && (item.Selected || item.Pressed);
        var on = item is ToolStripButton { Checked: true };
        Color fill, border;
        switch (kind)
        {
            case "primary":
                fill = !item.Enabled ? Theme.Mix(P.Accent, P.Surface, 0.45) : hot ? Theme.Mix(P.Accent, P.Dark ? Color.White : Color.Black, 0.12) : P.Accent;
                border = fill;
                break;
            case "pill":
                fill = on ? (hot ? Theme.Mix(P.GoodSoft, P.Good, 0.12) : P.GoodSoft) : hot ? P.Hover : P.Surface2;
                border = on ? fill : P.Border;
                break;
            default:
                fill = hot ? P.Hover : P.Surface;
                border = P.Border;
                break;
        }
        var r = new Rectangle(0, 0, item.Width - 1, item.Height - 1);
        var radius = kind == "pill" ? r.Height / 2 : item.Owner?.LogicalToDeviceUnits(7) ?? 7;
        Ui.FillRound(g, r, radius, fill, border);
    }

    protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
    {
        if (e.ToolStrip is not ToolStripDropDown) { base.OnRenderMenuItemBackground(e); return; }
        if (!e.Item.Selected || !e.Item.Enabled) return;
        var s = e.ToolStrip.LogicalToDeviceUnits(4);
        Ui.FillRound(e.Graphics, new Rectangle(s, 1, e.Item.Width - 2 * s, e.Item.Height - 2), s, P.Hover);
    }

    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
    {
        var kind = e.Item.Tag as string;
        Color c;
        if (!e.Item.Enabled) c = kind == "primary" ? P.AccentText : Theme.Mix(P.Text, P.Surface, 0.55);
        else if (e.ToolStrip is ToolStripDropDown) c = P.Text;
        else if (kind == "primary") c = P.AccentText;
        else if (kind == "pill") c = e.Item is ToolStripButton { Checked: true } ? P.Good : P.Muted;
        else if (kind == "muted") c = P.Muted;
        else if (e.Item is ToolStripStatusLabel { IsLink: true }) c = P.Link;
        else c = P.Text;
        TextRenderer.DrawText(e.Graphics, e.Text, e.TextFont, e.TextRectangle, c, e.TextFormat);
    }

    protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
    {
        using var pen = new Pen(P.Border);
        var r = e.Item.ContentRectangle;
        if (e.Vertical) { var x = e.Item.Width / 2; e.Graphics.DrawLine(pen, x, r.Top + 4, x, r.Bottom - 4); }
        else { var y = e.Item.Height / 2; e.Graphics.DrawLine(pen, r.Left + 4, y, r.Right - 4, y); }
    }

    protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
    {
        e.ArrowColor = P.Muted;
        base.OnRenderArrow(e);
    }

    protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e)
    {
        var r = e.ImageRectangle;
        r.Inflate(2, 2);
        Ui.FillRound(e.Graphics, r, 4, P.AccentSoft);
        TextRenderer.DrawText(e.Graphics, "✓", Theme.Bold, r, P.AccentSoftText, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
    }
}

/// <summary>The logo with "NetFinder" and the company under it.</summary>
internal sealed class BrandItem : ToolStripItem
{
    private readonly Image? _logo = Theme.Logo();
    public BrandItem() { Margin = new Padding(0, 0, 14, 0); }
    private int S(int v) => Owner?.LogicalToDeviceUnits(v) ?? v;

    public override Size GetPreferredSize(Size constrainingSize)
    {
        var name = TextRenderer.MeasureText(AppInfo.Name, Theme.Big, Size.Empty, TextFormatFlags.NoPadding);
        var sub = TextRenderer.MeasureText(AppInfo.Company, Theme.Small, Size.Empty, TextFormatFlags.NoPadding);
        return new Size(S(34) + S(10) + Math.Max(name.Width, sub.Width) + S(2), Math.Max(S(36), name.Height + sub.Height));
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        var size = S(34);
        if (_logo != null)
        {
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.DrawImage(_logo, new Rectangle(0, (Height - size) / 2, size, size));
        }
        var x = size + S(10);
        var name = TextRenderer.MeasureText(g, AppInfo.Name, Theme.Big, Size.Empty, TextFormatFlags.NoPadding);
        var sub = TextRenderer.MeasureText(g, AppInfo.Company, Theme.Small, Size.Empty, TextFormatFlags.NoPadding);
        var top = (Height - name.Height - sub.Height) / 2;
        TextRenderer.DrawText(g, AppInfo.Name, Theme.Big, new Point(x, top), Theme.P.Text, TextFormatFlags.NoPadding);
        TextRenderer.DrawText(g, AppInfo.Company, Theme.Small, new Point(x, top + name.Height), Theme.P.Muted, TextFormatFlags.NoPadding);
    }
}

/// <summary>A text box with a rounded border (and an optional magnifier), for the header.</summary>
internal sealed class InputBox : Control
{
    public readonly TextBox Box = new() { BorderStyle = BorderStyle.None, Font = Theme.Header };
    public bool SearchIcon { get; init; }

    public InputBox(int width)
    {
        Ui.Painted(this);
        Controls.Add(Box);
        Size = new Size(LogicalToDeviceUnits(width), LogicalToDeviceUnits(34));
        Box.GotFocus += (_, _) => Invalidate();
        Box.LostFocus += (_, _) => Invalidate();
        Cursor = Cursors.IBeam;
        ApplyTheme();
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var left = LogicalToDeviceUnits(SearchIcon ? 32 : 11);
        Box.SetBounds(left, (Height - Box.Height) / 2, Math.Max(10, Width - left - LogicalToDeviceUnits(10)), Box.Height);
    }

    protected override void OnClick(EventArgs e) { base.OnClick(e); Box.Focus(); }

    public void ApplyTheme()
    {
        Box.BackColor = Theme.P.InputBg;
        Box.ForeColor = Theme.P.Text;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var P = Theme.P;
        var g = e.Graphics;
        g.Clear(Parent?.BackColor ?? P.Surface);
        Ui.FillRound(g, new Rectangle(0, 0, Width - 1, Height - 1), LogicalToDeviceUnits(7), P.InputBg, Box.Focused ? P.Accent : P.Border);
        if (SearchIcon)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using var pen = new Pen(P.Muted, Math.Max(1.4f, LogicalToDeviceUnits(14) / 10f));
            var d = LogicalToDeviceUnits(10);
            var x = LogicalToDeviceUnits(12);
            var y = Height / 2 - d / 2 - LogicalToDeviceUnits(1);
            g.DrawEllipse(pen, x, y, d, d);
            g.DrawLine(pen, x + d - 1, y + d - 1, x + d + LogicalToDeviceUnits(4), y + d + LogicalToDeviceUnits(4));
        }
    }
}

/// <summary>The left menu: device kinds and networks, each with its count.</summary>
internal sealed class NavList : Control
{
    public sealed class Item
    {
        public string Key = "";
        public string Text = "";
        public string? Sub;
        public int Count;
        public bool Hidden;
        public bool IsSection;
    }

    public readonly List<Item> Items = new();
    public string SelectedKey { get; private set; } = "all";
    public event Action<string>? SelectedChanged;
    private readonly List<(Item Item, Rectangle R)> _layout = new();
    private int _hover = -1;

    public NavList() { Ui.Painted(this); }
    private int S(int v) => LogicalToDeviceUnits(v);

    public Item Section(string text) { var i = new Item { Text = text.ToUpperInvariant(), IsSection = true }; Items.Add(i); return i; }
    public Item Add(string key, string text) { var i = new Item { Key = key, Text = text }; Items.Add(i); return i; }
    public Item? Find(string key) => Items.FirstOrDefault(i => i.Key == key);
    public string TextOf(string key) => Find(key)?.Text ?? "";

    public void Select(string key)
    {
        if (key == SelectedKey) return;
        SelectedKey = key;
        Invalidate();
        SelectedChanged?.Invoke(key);
    }

    private void DoLayout()
    {
        _layout.Clear();
        var y = S(14);
        var first = true;
        foreach (var i in Items)
        {
            if (i.Hidden) continue;
            int h;
            if (i.IsSection) { if (!first) y += S(16); h = S(24); }
            else h = i.Sub != null ? S(48) : S(36);
            _layout.Add((i, new Rectangle(S(10), y, Width - S(20), h)));
            y += h + S(2);
            first = false;
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var P = Theme.P;
        var g = e.Graphics;
        g.Clear(P.Surface2);
        DoLayout();
        for (var n = 0; n < _layout.Count; n++)
        {
            var (i, r) = _layout[n];
            if (i.IsSection)
            {
                TextRenderer.DrawText(g, i.Text, Theme.Section, new Rectangle(r.X + S(10), r.Y, r.Width - S(10), r.Height), P.Muted, Ui.Line);
                continue;
            }
            var sel = i.Key == SelectedKey;
            if (sel) Ui.FillRound(g, r, S(8), P.AccentSoft);
            else if (n == _hover) Ui.FillRound(g, r, S(8), P.Hover);
            var font = sel ? Theme.HeaderBold : Theme.Header;
            var count = i.Count.ToString();
            var cw = TextRenderer.MeasureText(g, count, font, Size.Empty, TextFormatFlags.NoPadding).Width;
            var lineH = S(36);
            var textR = new Rectangle(r.X + S(12), r.Y + (i.Sub != null ? S(5) : 0), r.Width - S(24) - cw - S(6), i.Sub != null ? S(22) : lineH);
            TextRenderer.DrawText(g, i.Text, font, textR, sel ? P.AccentSoftText : P.Text, Ui.Line);
            TextRenderer.DrawText(g, count, font, new Rectangle(r.Right - S(12) - cw, textR.Y, cw + 2, textR.Height),
                sel ? P.AccentSoftText : i.Count == 0 ? Theme.Mix(P.Muted, P.Surface2, 0.35) : P.Muted, Ui.Line);
            if (i.Sub != null)
                TextRenderer.DrawText(g, i.Sub, Theme.Small, new Rectangle(textR.X, textR.Bottom, r.Width - S(24), S(18)), sel ? P.AccentSoftText : P.Muted, Ui.Line);
        }
    }

    private int HitTest(Point p)
    {
        for (var n = 0; n < _layout.Count; n++)
            if (!_layout[n].Item.IsSection && _layout[n].R.Contains(p)) return n;
        return -1;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var h = HitTest(e.Location);
        Cursor = h >= 0 ? Cursors.Hand : Cursors.Default;
        if (h != _hover) { _hover = h; Invalidate(); }
    }

    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); if (_hover != -1) { _hover = -1; Invalidate(); } }

    protected override void OnMouseClick(MouseEventArgs e)
    {
        base.OnMouseClick(e);
        var h = HitTest(e.Location);
        if (h >= 0) Select(_layout[h].Item.Key);
    }
}

/// <summary>A small rounded card: a colored title and a muted text under it (capture mode in the side menu).</summary>
internal sealed class InfoCard : Control
{
    public enum Kind { Good, Warn, Accent }
    private string _title = "", _body = "";
    public Kind Tone { get; set; }
    public string Title { get => _title; set { _title = value; FitHeight(); Invalidate(); } }
    public string Body { get => _body; set { _body = value; FitHeight(); Invalidate(); } }

    public InfoCard() { Ui.Painted(this); Cursor = Cursors.Hand; }
    private int S(int v) => LogicalToDeviceUnits(v);

    public void FitHeight()
    {
        var w = Width - S(28);
        Height = S(12) + Ui.WrapHeight(_title, Theme.Bold, w) + S(3) + Ui.WrapHeight(_body, Theme.Small, w) + S(12);
    }

    protected override void OnResize(EventArgs e) { base.OnResize(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var P = Theme.P;
        var g = e.Graphics;
        g.Clear(Parent?.BackColor ?? P.Surface2);
        var fill = Tone switch { Kind.Warn => P.WarnSoft, Kind.Accent => P.AccentSoft, _ => P.Dark ? P.Surface : Theme.Mix(P.Surface2, P.Border, 0.45) };
        Ui.FillRound(g, new Rectangle(0, 0, Width - 1, Height - 1), S(8), fill);
        var w = Width - S(28);
        var th = Ui.WrapHeight(_title, Theme.Bold, w);
        TextRenderer.DrawText(g, _title, Theme.Bold, new Rectangle(S(14), S(12), w, th), Tone switch { Kind.Warn => P.Warn, Kind.Accent => P.AccentSoftText, _ => P.Good }, Ui.Wrap);
        TextRenderer.DrawText(g, _body, Theme.Small, new Rectangle(S(14), S(12) + th + S(3), w, Height), P.Muted, Ui.Wrap);
        if (!Enabled) using (var b = new SolidBrush(Color.FromArgb(110, P.Surface2))) g.FillRectangle(b, ClientRectangle);
    }

    protected override void OnEnabledChanged(EventArgs e) { base.OnEnabledChanged(e); Invalidate(); }
}

/// <summary>Overview / All details / Log, as a segmented switch.</summary>
internal sealed class SegmentedTabs : Control
{
    private readonly List<string> _tabs = new();
    private int _selected, _hover = -1;
    public event Action<int>? SelectedIndexChanged;

    public SegmentedTabs(params string[] tabs) { Ui.Painted(this); _tabs.AddRange(tabs); Height = LogicalToDeviceUnits(38); Cursor = Cursors.Hand; }
    private int S(int v) => LogicalToDeviceUnits(v);

    public int SelectedIndex
    {
        get => _selected;
        set { if (value == _selected) return; _selected = value; Invalidate(); SelectedIndexChanged?.Invoke(value); }
    }

    public void SetText(int i, string text) { if (_tabs[i] == text) return; _tabs[i] = text; Invalidate(); }

    private Rectangle Seg(int i)
    {
        var inner = new Rectangle(S(3), S(3), Width - S(6) - 1, Height - S(6) - 1);
        var w = inner.Width / _tabs.Count;
        return new Rectangle(inner.X + i * w, inner.Y, i == _tabs.Count - 1 ? inner.Right - (inner.X + i * w) : w, inner.Height);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var P = Theme.P;
        var g = e.Graphics;
        g.Clear(Parent?.BackColor ?? P.Surface);
        Ui.FillRound(g, new Rectangle(0, 0, Width - 1, Height - 1), S(9), P.Dark ? P.Surface2 : Theme.Mix(P.Surface2, P.Border, 0.5));
        for (var i = 0; i < _tabs.Count; i++)
        {
            var r = Seg(i);
            var sel = i == _selected;
            if (sel) Ui.FillRound(g, r, S(7), P.Dark ? P.AccentSoft : P.Surface, P.Dark ? null : P.Border);
            else if (i == _hover) Ui.FillRound(g, r, S(7), P.Hover);
            TextRenderer.DrawText(g, _tabs[i], sel ? Theme.HeaderBold : Theme.Header, r, sel ? (P.Dark ? P.AccentSoftText : P.Text) : P.Muted,
                Ui.Line | TextFormatFlags.HorizontalCenter);
        }
    }

    private int Hit(Point p) { for (var i = 0; i < _tabs.Count; i++) if (Seg(i).Contains(p)) return i; return -1; }
    protected override void OnMouseMove(MouseEventArgs e) { base.OnMouseMove(e); var h = Hit(e.Location); if (h != _hover) { _hover = h; Invalidate(); } }
    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); _hover = -1; Invalidate(); }
    protected override void OnMouseClick(MouseEventArgs e) { base.OnMouseClick(e); var h = Hit(e.Location); if (h >= 0) SelectedIndex = h; }
}

/// <summary>Top of the details pane: the type tile, the IP big, and the name / MAC under it.</summary>
internal sealed class DetailsHeader : Control
{
    private string? _type;
    private string _title = "", _sub = "";
    public DetailsHeader() { Ui.Painted(this); Height = LogicalToDeviceUnits(64); }
    private int S(int v) => LogicalToDeviceUnits(v);

    public void Show(string? type, string title, string sub)
    {
        if (type == _type && title == _title && sub == _sub) return;
        _type = type; _title = title; _sub = sub;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var P = Theme.P;
        var g = e.Graphics;
        g.Clear(Parent?.BackColor ?? P.Surface);
        var x = 0;
        if (_type != null)
        {
            var size = S(48);
            Theme.DrawTypeTile(g, new Rectangle(0, S(4), size, size), _type, Parent?.BackColor ?? P.Surface);
            x = size + S(14);
        }
        var titleFont = _type != null ? Theme.MonoTitle : Theme.Big;
        var th = TextRenderer.MeasureText(g, _title, titleFont, Size.Empty, TextFormatFlags.NoPadding).Height;
        TextRenderer.DrawText(g, _title, titleFont, new Rectangle(x, S(2), Width - x, th), P.Text, Ui.Line);
        TextRenderer.DrawText(g, _sub, Theme.Base, new Rectangle(x, S(4) + th, Width - x, Height - th - S(4)), P.Muted, Ui.Wrap | TextFormatFlags.EndEllipsis);
    }
}

/// <summary>A rounded button: outlined, or filled with the accent color (Primary).</summary>
internal sealed class RoundButton : Control
{
    private bool _hot;
    public bool Primary { get; set; }

    public RoundButton(string text, bool primary = false)
    {
        Ui.Painted(this);
        Primary = primary;
        Font = primary ? Theme.Bold : Theme.Base;
        Cursor = Cursors.Hand;
        Text = text;
        Margin = new Padding(0, LogicalToDeviceUnits(4), LogicalToDeviceUnits(8), LogicalToDeviceUnits(4));
    }

    public override Size GetPreferredSize(Size proposedSize)
    {
        var t = TextRenderer.MeasureText(Text, Font, Size.Empty, TextFormatFlags.NoPadding);
        return new Size(t.Width + LogicalToDeviceUnits(28), Math.Max(LogicalToDeviceUnits(32), t.Height + LogicalToDeviceUnits(14)));
    }

    protected override void OnTextChanged(EventArgs e) { base.OnTextChanged(e); Size = GetPreferredSize(Size.Empty); Invalidate(); }
    protected override void OnFontChanged(EventArgs e) { base.OnFontChanged(e); Size = GetPreferredSize(Size.Empty); }
    protected override void OnMouseEnter(EventArgs e) { base.OnMouseEnter(e); _hot = true; Invalidate(); }
    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); _hot = false; Invalidate(); }
    protected override void OnEnabledChanged(EventArgs e) { base.OnEnabledChanged(e); Invalidate(); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var P = Theme.P;
        var g = e.Graphics;
        g.Clear(Parent?.BackColor ?? P.Surface);
        var hot = _hot && Enabled;
        Color fill, border, text;
        if (Primary)
        {
            fill = !Enabled ? Theme.Mix(P.Accent, P.Surface, 0.45) : hot ? Theme.Mix(P.Accent, P.Dark ? Color.White : Color.Black, 0.12) : P.Accent;
            border = fill; text = P.AccentText;
        }
        else
        {
            fill = hot ? P.Hover : P.Surface; border = P.Border; text = Enabled ? P.Text : P.Muted;
        }
        Ui.FillRound(g, new Rectangle(0, 0, Width - 1, Height - 1), LogicalToDeviceUnits(7), fill, border);
        TextRenderer.DrawText(g, Text, Font, ClientRectangle, text, Ui.Line | TextFormatFlags.HorizontalCenter);
    }
}

/// <summary>
/// A rounded table of name / value rows (hardware, all details). A value can carry a chip ("SSD · 256 GB")
/// and a bar (how full a drive is). Right-click copies it.
/// </summary>
internal sealed class InfoTable : Control
{
    public sealed record Row(string Key, string Value, string? Chip = null, bool ChipGood = false, double? Bar = null);
    public string? Title { get; set; }
    public readonly List<Row> Rows = new();
    public int KeyWidth { get; set; } = 112;
    private readonly List<(Row Row, Rectangle R, int ValueH)> _layout = new();

    public InfoTable()
    {
        Ui.Painted(this);
        var menu = new ContextMenuStrip { Renderer = new ChromeRenderer() };
        menu.Items.Add("Copy", null, (_, _) => { var t = ToText(); if (t.Length > 0) Clipboard.SetText(t); });
        ContextMenuStrip = menu;
    }

    private int S(int v) => LogicalToDeviceUnits(v);
    public string ToText() => string.Join("\r\n", Rows.Select(r => $"{r.Key}: {r.Value}{(r.Chip != null ? $" ({r.Chip})" : "")}"));

    /// <summary>Sets the width and grows to fit every row.</summary>
    public void Fit(int width)
    {
        Width = width;
        _layout.Clear();
        var y = Title != null ? S(38) : 0;
        var valueW = Width - S(KeyWidth) - S(32);
        foreach (var r in Rows)
        {
            var vh = Math.Max(Ui.WrapHeight(r.Value, Theme.Base, valueW), Ui.WrapHeight(r.Key, Theme.Base, S(KeyWidth) - S(8)));
            var h = S(10) + vh + (r.Chip != null ? S(26) : 0) + (r.Bar != null ? S(14) : 0) + S(10);
            _layout.Add((r, new Rectangle(0, y, Width, h), vh));
            y += h;
        }
        Height = Math.Max(y + 1, S(20));
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var P = Theme.P;
        var g = e.Graphics;
        g.Clear(Parent?.BackColor ?? P.Surface);
        var outer = new Rectangle(0, 0, Width - 1, Height - 1);
        Ui.FillRound(g, outer, S(9), P.Surface, P.Border);
        using var line = new Pen(P.Border);
        if (Title != null)
        {
            var band = new Rectangle(1, 1, Width - 3, S(37) - 1);
            using (var path = TopRounded(band, S(8)))
            using (var b = new SolidBrush(P.Surface2))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.FillPath(b, path);
                g.SmoothingMode = SmoothingMode.None;
            }
            TextRenderer.DrawText(g, Title.ToUpperInvariant(), Theme.Section, new Rectangle(S(16), 0, Width - S(32), S(37)), P.Muted, Ui.Line);
            g.DrawLine(line, 1, S(37), Width - 2, S(37));
        }
        var keyW = S(KeyWidth);
        var valueX = S(16) + keyW;
        var valueW = Width - keyW - S(32);
        for (var n = 0; n < _layout.Count; n++)
        {
            var (row, r, vh) = _layout[n];
            if (n > 0) g.DrawLine(line, 1, r.Y, Width - 2, r.Y);
            TextRenderer.DrawText(g, row.Key, Theme.Base, new Rectangle(S(16), r.Y + S(10), keyW - S(8), vh), P.Muted, Ui.Wrap);
            TextRenderer.DrawText(g, row.Value, Theme.Base, new Rectangle(valueX, r.Y + S(10), valueW, vh), P.Text, Ui.Wrap);
            var y = r.Y + S(10) + vh;
            if (row.Chip != null)
            {
                var tw = TextRenderer.MeasureText(g, row.Chip, Theme.Bold, Size.Empty, TextFormatFlags.NoPadding).Width;
                var chip = new Rectangle(valueX, y + S(5), tw + S(18), S(20));
                Ui.FillRound(g, chip, S(10), row.ChipGood ? P.GoodSoft : P.Hover, row.ChipGood ? null : P.Border);
                TextRenderer.DrawText(g, row.Chip, Theme.Bold, chip, row.ChipGood ? P.Good : P.Muted, Ui.Line | TextFormatFlags.HorizontalCenter);
                y += S(26);
            }
            if (row.Bar is { } used)
            {
                var track = new Rectangle(valueX, y + S(6), valueW, S(5));
                Ui.FillRound(g, track, S(3), P.Bar);
                var w = (int)Math.Round(track.Width * Math.Clamp(used, 0, 1));
                if (w > 2) Ui.FillRound(g, new Rectangle(track.X, track.Y, w, track.Height), S(3), used > 0.9 ? P.Warn : P.Accent);
            }
        }
    }

    private static GraphicsPath TopRounded(Rectangle r, int radius)
    {
        var d = radius * 2;
        var p = new GraphicsPath();
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddLine(r.Right, r.Bottom, r.X, r.Bottom);
        p.CloseFigure();
        return p;
    }
}

/// <summary>Open ports as rounded chips: "445 File sharing".</summary>
internal sealed class ChipList : Control
{
    public readonly List<(string Bold, string Text, string? Tip)> Chips = new();
    private readonly List<(Rectangle R, int Index)> _layout = new();
    private readonly ToolTip _tip = new();
    private int _tipFor = -1;

    public ChipList() { Ui.Painted(this); }
    private int S(int v) => LogicalToDeviceUnits(v);

    private int ChipWidth((string Bold, string Text, string? Tip) c) =>
        TextRenderer.MeasureText(c.Bold, Theme.Bold, Size.Empty, TextFormatFlags.NoPadding).Width +
        (c.Text.Length > 0 ? S(5) + TextRenderer.MeasureText(c.Text, Theme.Base, Size.Empty, TextFormatFlags.NoPadding).Width : 0) + S(24);

    public void Fit(int width)
    {
        Width = width;
        _layout.Clear();
        int x = 0, y = 0, h = S(28);
        for (var i = 0; i < Chips.Count; i++)
        {
            var w = Math.Min(ChipWidth(Chips[i]), width - 1);
            if (x > 0 && x + w > width) { x = 0; y += h + S(6); }
            _layout.Add((new Rectangle(x, y, w, h), i));
            x += w + S(6);
        }
        Height = _layout.Count == 0 ? 0 : y + h + 1;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var P = Theme.P;
        var g = e.Graphics;
        g.Clear(Parent?.BackColor ?? P.Surface);
        foreach (var (r, i) in _layout)
        {
            var c = Chips[i];
            Ui.FillRound(g, r, r.Height / 2, P.Dark ? P.Surface2 : Theme.Mix(P.Surface2, P.Border, 0.45), P.Dark ? P.Border : null);
            var bw = TextRenderer.MeasureText(g, c.Bold, Theme.Bold, Size.Empty, TextFormatFlags.NoPadding).Width;
            TextRenderer.DrawText(g, c.Bold, Theme.Bold, new Rectangle(r.X + S(12), r.Y, bw + 2, r.Height), P.Text, Ui.Line);
            if (c.Text.Length > 0)
                TextRenderer.DrawText(g, c.Text, Theme.Base, new Rectangle(r.X + S(12) + bw + S(5), r.Y, r.Right - (r.X + S(12) + bw + S(5)) - S(10), r.Height), P.Text, Ui.Line);
        }
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var hit = _layout.FindIndex(l => l.R.Contains(e.Location));
        if (hit == _tipFor) return;
        _tipFor = hit;
        _tip.SetToolTip(this, hit >= 0 ? Chips[_layout[hit].Index].Tip ?? "" : "");
    }
}

internal static class Native
{
    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] private static extern int SetWindowTheme(IntPtr hwnd, string? app, string? idList);
    [DllImport("user32.dll")] private static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int cx, int cy, uint flags);

    /// <summary>Dark title bar on Windows 10 (2004+) and 11.</summary>
    public static void DarkTitleBar(Form f, bool dark)
    {
        if (!f.IsHandleCreated) return;
        var v = dark ? 1 : 0;
        try { if (DwmSetWindowAttribute(f.Handle, 20, ref v, 4) != 0) DwmSetWindowAttribute(f.Handle, 19, ref v, 4); } catch { }
    }

    /// <summary>Dark scroll bars (and combo box) for a control and the scroll bars inside it.</summary>
    public static void DarkScrollbars(Control c, bool dark)
    {
        try
        {
            if (c.IsHandleCreated) SetWindowTheme(c.Handle, dark ? (c is ComboBox ? "DarkMode_CFD" : "DarkMode_Explorer") : "Explorer", null);
            foreach (Control child in c.Controls)
                if (child is ScrollBar && child.IsHandleCreated) SetWindowTheme(child.Handle, dark ? "DarkMode_Explorer" : "Explorer", null);
        }
        catch { }
    }

    /// <summary>Resizes a window past the screen size (screenshots on a small screen).</summary>
    public static void ForceSize(Form f, int width, int height)
    {
        try { SetWindowPos(f.Handle, IntPtr.Zero, 0, 0, width, height, 0x0002 | 0x0004 | 0x0010); } catch { }
    }
}
