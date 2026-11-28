using System.Drawing.Drawing2D;
using System.Text;
using System.Text.RegularExpressions;
using NetFinder.Core;
using NetFinder.Core.Model;
using NetFinder.Core.Net;

namespace NetFinder.Ui;

/// <summary>Colors of toner / ink (readable in light and dark).</summary>
internal static class Ink
{
    public static Color For(string? color)
    {
        var P = Theme.P;
        var c = color?.ToLowerInvariant() ?? "";
        if (c.Contains("black")) return P.Dark ? Theme.Hex("C9D1D9") : Theme.Hex("27313D");
        if (c.Contains("cyan")) return Theme.Hex("00A3D9");
        if (c.Contains("magenta")) return Theme.Hex("D6338A");
        if (c.Contains("yellow")) return P.Dark ? Theme.Hex("F2C94C") : Theme.Hex("E0AC00");
        if (c.Contains("red")) return Theme.Hex("D64545");
        if (c.Contains("blue")) return Theme.Hex("3D6FD9");
        if (c.Contains("green")) return Theme.Hex("2E9E5B");
        if (c.Contains("gray") || c.Contains("grey")) return Theme.Hex("8A949E");
        return P.Accent;
    }

    /// <summary>The supplies worth showing in a list: the colorants, or all of them when none is marked as one.</summary>
    public static IReadOnlyList<PrinterSupply> Shown(PrinterState p) =>
        p.Supplies.Any(s => s.IsColorant) ? p.Supplies.Where(s => s.IsColorant).ToList() : p.Supplies;

    /// <summary>"62%", "OK", "Unknown" (a waste box: "35% full").</summary>
    public static string Level(PrinterSupply s) => s.Percent is { } p ? s.FillsUp ? $"{p}% full" : $"{p}%" : s.State;

    /// <summary>Paints "● 62%  ● 18%  ● 9%  ● OK" in a list cell (low ones in red).</summary>
    public static void PaintCell(Graphics g, Rectangle cell, PrinterState p, Func<int, int> Sx)
    {
        var P = Theme.P;
        var x = cell.X + Sx(8);
        var dot = Sx(9);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        foreach (var s in Shown(p))
        {
            var text = Level(s);
            var font = s.Low ? Theme.Bold : Theme.Base;
            var tw = TextRenderer.MeasureText(g, text, font, Size.Empty, TextFormatFlags.NoPadding).Width;
            if (x + dot + Sx(4) + tw > cell.Right - Sx(4)) break;
            using (var b = new SolidBrush(For(s.Color)))
                g.FillEllipse(b, x, cell.Y + (cell.Height - dot) / 2, dot, dot);
            x += dot + Sx(4);
            TextRenderer.DrawText(g, text, font, new Rectangle(x, cell.Y, tw + Sx(2), cell.Height), s.Low ? P.Bad : P.Text, Ui.Line);
            x += tw + Sx(10);
        }
        g.SmoothingMode = SmoothingMode.None;
    }
}

/// <summary>
/// A switch's ports as small squares, like the front of the switch: green = a device is plugged in, blue = several devices
/// (another switch or a Wi-Fi access point), light green = link up but nothing learned, gray = nothing plugged in, dashed = disabled.
/// </summary>
internal sealed class PortGrid : Control
{
    public readonly List<(SwitchPort Port, string Tip)> Ports = new();
    public event Action<SwitchPort>? PortClicked;
    private readonly List<(Rectangle R, int Index)> _layout = new();
    private readonly ToolTip _tip = new() { InitialDelay = 200, ReshowDelay = 100, AutoPopDelay = 20000 };
    private int _hover = -1;

    public PortGrid() { Ui.Painted(this); Cursor = Cursors.Hand; }
    private int S(int v) => LogicalToDeviceUnits(v);
    private int Box => Math.Max(S(30), TextRenderer.MeasureText("48", Theme.Small).Width + S(10));

    public void Fit(int width)
    {
        Width = width;
        _layout.Clear();
        var size = Box; var gap = S(5);
        var perRow = Math.Max(1, (width + gap) / (size + gap));
        // keep the rows even (a 24-port switch as 2 × 12, not 16 + 8) when it costs no extra row
        var rows = (Ports.Count + perRow - 1) / perRow;
        if (rows > 1) perRow = (Ports.Count + rows - 1) / rows;
        for (var i = 0; i < Ports.Count; i++)
            _layout.Add((new Rectangle(i % perRow * (size + gap), i / perRow * (size + gap), size, size), i));
        Height = Math.Max(size, rows * (size + gap) - gap) + 1;
        Invalidate();
    }

    /// <summary>"1/1/7" → "7", "Gi1/0/24" → "24", "Trk1" → "Trk1", "Port 5" → "5".</summary>
    public static string Label(string name)
    {
        var m = Regex.Match(name, @"(\d+)$");
        if (!m.Success) return name.Length > 4 ? name[..4] : name;
        var lead = name[..m.Index];
        return Regex.IsMatch(lead, @"^(port\s*|.*[/:.\s-]|[a-z]{1,3}|gi|fa|te|ge|xe|eth|ethernet|gigabitethernet\s*)$", RegexOptions.IgnoreCase) || lead.Length == 0
            ? m.Value : (lead.Length <= 3 ? lead + m.Value : m.Value);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var P = Theme.P;
        var g = e.Graphics;
        g.Clear(Parent?.BackColor ?? P.Surface);
        foreach (var (r, i) in _layout)
        {
            var p = Ports[i].Port;
            var many = p.Macs.Count >= 3;
            Color fill, border, text;
            if (p.Disabled) { fill = P.Surface2; border = P.Border; text = P.Muted; }
            else if (!p.Up) { fill = P.Bar; border = P.Bar; text = P.Muted; }
            else if (p.Macs.Count == 0) { fill = P.GoodSoft; border = Theme.Mix(P.Good, P.Surface, 0.55); text = P.Good; }
            else if (many) { fill = P.Accent; border = P.Accent; text = P.AccentText; }
            else { fill = P.Good; border = P.Good; text = P.Dark ? P.Bg : Color.White; }
            if (i == _hover) border = P.Text;
            Ui.FillRound(g, r, S(6), fill, border);
            if (p.Disabled)
            {
                using var pen = new Pen(P.Muted) { DashStyle = DashStyle.Dash };
                g.DrawLine(pen, r.X + S(5), r.Bottom - S(6), r.Right - S(6), r.Y + S(5));
            }
            TextRenderer.DrawText(g, Label(p.Name), Theme.Small, r, text, Ui.Line | TextFormatFlags.HorizontalCenter);
        }
    }

    private int HitTest(Point pt) => _layout.FirstOrDefault(l => l.R.Contains(pt)) is var hit && hit.R.Width > 0 ? hit.Index : -1;

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var i = HitTest(e.Location);
        if (i == _hover) return;
        _hover = i;
        Invalidate();
        if (i >= 0) _tip.Show(Ports[i].Tip, this, _layout[i].R.Left, _layout[i].R.Bottom + S(4), 20000);
        else _tip.Hide(this);
    }

    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); _hover = -1; _tip.Hide(this); Invalidate(); }

    protected override void OnMouseClick(MouseEventArgs e)
    {
        base.OnMouseClick(e);
        var i = HitTest(e.Location);
        if (i >= 0) PortClicked?.Invoke(Ports[i].Port);
    }

    protected override void Dispose(bool disposing) { if (disposing) _tip.Dispose(); base.Dispose(disposing); }
}

/// <summary>Who is behind each MAC address of a switch: the devices of the main list, else the maker from the MAC.</summary>
internal static class PortPeople
{
    public static Dictionary<string, List<Device>> ByMac(IEnumerable<Device> all)
    {
        var map = new Dictionary<string, List<Device>>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in all)
        {
            string mac;
            lock (d) mac = d.Mac.Length > 0 ? d.Mac : d.Info.GetValueOrDefault(PortMap.ArpMacKey) ?? "";
            if (mac.Length == 0) continue;
            if (!map.TryGetValue(mac, out var l)) map[mac] = l = new();
            l.Add(d);
        }
        return map;
    }

    /// <summary>"acc-pc07 10.0.0.45 (Windows PC)" or "MAC 64:A2:F9:01:02:58 (OnePlus)".</summary>
    public static string Who(string mac, Dictionary<string, List<Device>> byMac)
    {
        if (byMac.TryGetValue(mac, out var l) && l.Count > 0)
        {
            var d = l[0];
            lock (d)
            {
                var name = d.DisplayName.Length > 0 ? d.DisplayName + " " : "";
                return $"{name}{d.Ip} ({(d.IsSelf ? "this PC" : d.EffectiveType)})" + (l.Count > 1 ? $" +{l.Count - 1} IP" : "");
            }
        }
        var vendor = OuiLookup.Lookup(mac);
        return $"MAC {mac}" + (string.IsNullOrEmpty(vendor) ? "" : $" ({Core.Export.DeviceText.ShortVendor(vendor)})");
    }

    public static string Tip(SwitchPort p, Dictionary<string, List<Device>> byMac)
    {
        var sb = new StringBuilder();
        sb.Append($"Port {p.Name} · {p.StatusText}");
        if (p.SpeedText.Length > 0) sb.Append($" · {p.SpeedText}");
        if (p.Alias != null) sb.Append($"\n\"{p.Alias}\"");
        if (p.Vlans.Count > 0) sb.Append($"\nVLAN {string.Join(", ", p.Vlans)}");
        if (p.Macs.Count > 0)
        {
            sb.Append(p.Macs.Count >= 3 ? $"\n{p.Macs.Count} devices (another switch or a Wi-Fi access point):" : "\n");
            foreach (var m in p.Macs.Take(8)) sb.Append("\n• " + Who(m, byMac));
            if (p.Macs.Count > 8) sb.Append($"\n… and {p.Macs.Count - 8} more");
        }
        else if (p.Up) sb.Append("\nLink up, no device learned yet");
        return sb.ToString();
    }
}

/// <summary>"Show ports": every port of a switch, its status and speed, and the devices plugged into it.</summary>
internal sealed class SwitchPortsForm : Form
{
    private readonly DataGridView _grid = new();
    private readonly Label _head = new() { AutoSize = true, Font = Theme.HeaderBold, UseMnemonic = false };
    private readonly Label _note = new() { AutoSize = true, UseMnemonic = false };
    private readonly CheckBox _inUse = new() { Text = "Only ports with a device", AutoSize = true };
    private readonly Action<Device> _select;
    private readonly List<(SwitchPort Port, string Who, string All, int Count)> _rows = new();
    private readonly string _title;

    public SwitchPortsForm(Device sw, IEnumerable<Device> all, Action<Device> select)
    {
        _select = select;
        SwitchState st; string ip, name, model;
        lock (sw) { st = sw.Switch!; ip = sw.Ip?.ToString() ?? ""; name = sw.DisplayName; model = sw.Model ?? ""; }
        var byMac = PortPeople.ByMac(all);
        _title = name.Length > 0 && name != model ? $"{name} ({ip})" : ip;
        Text = $"Ports of switch {_title}";
        Font = Theme.Base;
        Icon = Theme.AppIcon();
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        var line = TextRenderer.MeasureText("Wg", Theme.Base).Height;
        ClientSize = new Size(line * 64, line * 34);
        MinimumSize = new Size(line * 40, line * 20);
        var P = Theme.P;
        BackColor = P.Surface;
        ForeColor = P.Text;

        foreach (var p in st.Ports)
        {
            var who = p.Macs.Select(m => PortPeople.Who(m, byMac)).ToList();
            var shown = who.Count <= 2 ? string.Join(", ", who) : $"{p.Macs.Count} devices: " + string.Join(", ", who.Take(2)) + ", …";
            _rows.Add((p, shown, string.Join("\n", who), p.Macs.Count));
        }

        _head.Text = $"{_title}{(model.Length > 0 ? "  ·  " + model : "")}";
        _head.ForeColor = P.Text;
        _note.Text = $"{st.Up} of {st.Ports.Count} ports up  ·  {st.MacCount} devices learned  ·  read {st.ReadAt:HH:mm}.  " +
                     "A port with several devices leads to another switch or a Wi-Fi access point. Double-click a row to pick its device in the list.";
        _note.ForeColor = P.Muted;
        _inUse.ForeColor = P.Text;
        _inUse.CheckedChanged += (_, _) => Fill();

        BuildGrid();
        var top = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1, Padding = new Padding(LogicalToDeviceUnits(14), LogicalToDeviceUnits(12), LogicalToDeviceUnits(14), LogicalToDeviceUnits(6)), BackColor = P.Surface };
        _note.MaximumSize = new Size(ClientSize.Width - LogicalToDeviceUnits(30), 0);
        top.Controls.Add(_head);
        top.Controls.Add(_note);
        top.Controls.Add(_inUse);
        _note.Margin = new Padding(0, LogicalToDeviceUnits(4), 0, LogicalToDeviceUnits(4));
        Resize += (_, _) => _note.MaximumSize = new Size(Math.Max(100, ClientSize.Width - LogicalToDeviceUnits(30)), 0);

        var bottom = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(LogicalToDeviceUnits(10), LogicalToDeviceUnits(6), LogicalToDeviceUnits(10), LogicalToDeviceUnits(8)), BackColor = P.Surface };
        var copy = new Button { Text = "Copy list", AutoSize = true, UseVisualStyleBackColor = true };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel, UseVisualStyleBackColor = true };
        copy.Click += (_, _) => { Clipboard.SetText(ListText()); copy.Text = "Copied"; };
        bottom.Controls.AddRange(new Control[] { copy, close });
        CancelButton = close;

        var host = new Panel { Dock = DockStyle.Fill, Padding = new Padding(LogicalToDeviceUnits(14), LogicalToDeviceUnits(2), LogicalToDeviceUnits(14), 0), BackColor = P.Surface };
        host.Controls.Add(_grid);
        Controls.Add(host);
        Controls.Add(bottom);
        Controls.Add(top);
        Fill();
    }

    private void BuildGrid()
    {
        var P = Theme.P;
        _grid.Dock = DockStyle.Fill;
        _grid.ReadOnly = true;
        _grid.AllowUserToAddRows = false;
        _grid.AllowUserToDeleteRows = false;
        _grid.AllowUserToResizeRows = false;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.MultiSelect = false;
        _grid.BorderStyle = BorderStyle.None;
        _grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        _grid.EnableHeadersVisualStyles = false;
        _grid.BackgroundColor = P.Surface;
        _grid.GridColor = P.Border;
        _grid.DefaultCellStyle.BackColor = P.Surface;
        _grid.DefaultCellStyle.ForeColor = P.Text;
        _grid.DefaultCellStyle.SelectionBackColor = P.RowSelected;
        _grid.DefaultCellStyle.SelectionForeColor = P.Text;
        _grid.DefaultCellStyle.Padding = new Padding(LogicalToDeviceUnits(4), 0, LogicalToDeviceUnits(4), 0);
        _grid.ColumnHeadersDefaultCellStyle.BackColor = P.Surface2;
        _grid.ColumnHeadersDefaultCellStyle.ForeColor = P.Muted;
        _grid.ColumnHeadersDefaultCellStyle.Font = Theme.Bold;
        _grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
        _grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
        _grid.RowTemplate.Height = TextRenderer.MeasureText("Wg", Theme.Base).Height + LogicalToDeviceUnits(12);
        var line = TextRenderer.MeasureText("Wg", Theme.Base).Height;
        void Col(string name, string header, int widthInLines, bool fill = false)
        {
            var c = new DataGridViewTextBoxColumn { Name = name, HeaderText = header, Width = line * widthInLines, SortMode = DataGridViewColumnSortMode.NotSortable };
            if (fill) { c.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill; c.MinimumWidth = line * 8; }
            _grid.Columns.Add(c);
        }
        Col("Port", "Port", 5);
        Col("Status", "Status", 5);
        Col("Speed", "Speed", 5);
        Col("Alias", "Description", 9);
        Col("Vlan", "VLAN", 4);
        Col("Count", "Devices", 4);
        Col("Who", "Plugged in", 20, fill: true);
        _grid.CellDoubleClick += (_, e) =>
        {
            if (e.RowIndex < 0 || _grid.Rows[e.RowIndex].Tag is not SwitchPort p || p.Macs.Count == 0) return;
            _picked = p;
            DialogResult = DialogResult.OK;
        };
    }

    private SwitchPort? _picked;
    /// <summary>The port double-clicked (its device gets picked in the main list).</summary>
    public SwitchPort? Picked => _picked;

    private void Fill()
    {
        var P = Theme.P;
        _grid.Rows.Clear();
        foreach (var (p, who, all, count) in _rows)
        {
            if (_inUse.Checked && count == 0) continue;
            var i = _grid.Rows.Add(p.Name, p.StatusText, p.SpeedText, p.Alias ?? "", string.Join(",", p.Vlans), count == 0 ? "" : count.ToString(), who);
            var row = _grid.Rows[i];
            row.Tag = p;
            row.Cells["Status"].Style.ForeColor = p.Disabled ? P.Muted : p.Up ? P.Good : P.Muted;
            row.Cells["Status"].Style.Font = p.Up ? Theme.Bold : Theme.Base;
            if (count >= 3) row.Cells["Count"].Style.ForeColor = P.Accent;
            row.Cells["Who"].ToolTipText = all;
        }
    }

    private string ListText()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Switch {_title}");
        sb.AppendLine("Port\tStatus\tSpeed\tDescription\tVLAN\tDevices\tPlugged in");
        foreach (var (p, _, all, count) in _rows)
            sb.AppendLine(string.Join("\t", p.Name, p.StatusText, p.SpeedText, p.Alias, string.Join(",", p.Vlans), count, all.Replace("\n", "; ")));
        return sb.ToString();
    }
}
