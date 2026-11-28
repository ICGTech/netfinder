using NetFinder.Core;
using NetFinder.Core.Model;
using NetFinder.Core.Plugins;
using NetFinder.Core.Text;
using static NetFinder.Core.Text.L;

namespace NetFinder.Ui;

internal static class Dialogs
{
    public static string? Input(IWin32Window owner, string title, string prompt, string value)
    {
        using var d = new AutoDialog(title, 380);
        d.Text(prompt);
        var tb = d.Add(new TextBox { Text = value, Width = d.Width }, top: 6);
        d.Buttons("OK");
        return d.Show(owner) ? tb.Text.Trim() : null;
    }

    /// <summary>Windows login used to read a PC's model over WMI. Kept in memory only, never written to disk.</summary>
    public sealed record WindowsLogin(string User, string Password);

    /// <summary>Asks for a Windows admin login. Empty user = use the account running this program.</summary>
    public static WindowsLogin? AskWindowsLogin(IWin32Window owner, string target, WindowsLogin? current)
    {
        using var d = new AutoDialog(T("Windows login – read PC model"), 460);
        d.Text(T($"To read the model, serial number, CPU, RAM, disks and graphics card of {target}, log in with an account that is administrator on it " +
               $"(e.g. DOMAIN\\admin or PCNAME\\Administrator)."));
        var tu = new TextBox { Text = current?.User ?? "", PlaceholderText = T("DOMAIN\\user  or  user@domain.local") };
        var tp = new TextBox { UseSystemPasswordChar = true, Text = current?.Password ?? "" };
        Ui.Ltr(tu, tp);
        d.Fields(12, 0, (T("User:"), tu), (T("Password:"), tp));
        d.Text(T("Leave the user empty to use your own Windows login. Kept only while NetFinder is open; never saved to disk."), top: 4, muted: true, small: true);
        d.Buttons(T("Read model"));
        d.Form.Shown += (_, _) => (tu.Text.Length == 0 ? tu : tp).Focus();
        return d.Show(owner) ? new WindowsLogin(tu.Text.Trim(), tp.Text) : null;
    }

    public sealed record ModelsOptions(bool OtherSubnets, WindowsLogin? Login, bool StartRemoteRegistry);

    /// <summary>Options for "Get models" on the whole list.</summary>
    public static ModelsOptions? AskModelsOptions(IWin32Window owner, int devices, int otherSubnetDevices, int windowsPcs, WindowsLogin? current)
    {
        using var d = ModelsDialog(devices, otherSubnetDevices, windowsPcs, current, out var result);
        return d.Show(owner) ? result() : null;
    }

    /// <summary>The "Get models" dialog (also shown by the screenshot mode). Every text wraps, so nothing is cut at any Windows scaling.</summary>
    internal static AutoDialog ModelsDialog(int devices, int otherSubnetDevices, int windowsPcs, WindowsLogin? current, out Func<ModelsOptions> result)
    {
        var d = new AutoDialog(T("Get the model of every device"), 500);
        d.Text(T($"{devices} devices. Each one is asked for its model without a password (web page, UPnP, SNMP \"public\", ONVIF cameras, IPP printers)."));
        var other = d.Check(otherSubnetDevices == 1 ? T("Include the 1 device on another IP range") : T($"Include the {otherSubnetDevices} devices on other IP ranges"),
            otherSubnetDevices > 0, top: 12);
        other.Enabled = otherSubnetDevices > 0;
        d.Text(T("Adds a temporary IP on this PC's network card for each range; it is removed when NetFinder closes."), left: 18, muted: true);

        d.Text(T($"Windows PCs ({windowsPcs} found)"), top: 18, bold: true);
        d.Text(T("An admin login reads their model, serial number, CPU, RAM, disks and graphics card."), top: 2, muted: true);
        var useWin = d.Check(T("Use a Windows login"), current != null || windowsPcs > 0, top: 8);
        var tu = new TextBox { Text = current?.User ?? "", PlaceholderText = T("DOMAIN\\admin  or  admin@domain.local") };
        var tp = new TextBox { UseSystemPasswordChar = true, Text = current?.Password ?? "" };
        Ui.Ltr(tu, tp);
        d.Fields(4, 18, (T("User:"), tu), (T("Password:"), tp));
        d.Text(T("Empty user = your own Windows login. Kept only while NetFinder is open; never saved to disk."), top: 2, left: 18, muted: true, small: true);
        var reg = d.Check(T("If the firewall blocks WMI, read it over file sharing (port 445)"), true, top: 10, left: 18);
        d.Text(T("Starts the Remote Registry service for a moment when it is off, and puts it back right after."), left: 36, muted: true);
        void Sync() { tu.Enabled = tp.Enabled = reg.Enabled = useWin.Checked; }
        useWin.CheckedChanged += (_, _) => Sync();
        Sync();
        d.Buttons(T("Start"));
        result = () => new ModelsOptions(other.Checked, useWin.Checked ? new WindowsLogin(tu.Text.Trim(), tp.Text) : null, reg.Checked);
        return d;
    }

    /// <summary>A device in the "Watch devices" list. Group is the side-menu group ("server", "printer"…).</summary>
    public sealed record WatchPick(string Ip, string Mac, string Name, string Type, string Model, string Group, bool On);
    public sealed record WatchChoice(List<WatchPick> Devices, int Seconds, bool Sound);

    public static readonly (int Seconds, string Text)[] WatchIntervals =
        { (30, T("30 seconds")), (60, T("1 minute")), (120, T("2 minutes")), (300, T("5 minutes")), (600, T("10 minutes")) };

    public static string EveryText(int seconds) =>
        WatchIntervals.FirstOrDefault(i => i.Seconds == seconds).Text ?? (seconds % 60 == 0 ? T($"{seconds / 60} minutes") : T($"{seconds} seconds"));

    /// <summary>"Watch devices": tick the devices to ping, how often, and whether to play a sound.</summary>
    public static WatchChoice? AskWatch(IWin32Window owner, IReadOnlyList<WatchPick> devices, int seconds, bool sound)
    {
        using var d = WatchDialog(devices, seconds, sound, out var result);
        return d.Show(owner) ? result() : null;
    }

    internal static AutoDialog WatchDialog(IReadOnlyList<WatchPick> devices, int seconds, bool sound, out Func<WatchChoice> result)
    {
        var d = new AutoDialog(T("Watch devices"), 600);
        int S(int v) => d.Form.LogicalToDeviceUnits(v);
        d.Text(T("Tick the devices to watch. NetFinder pings each one and tells you as soon as it stops answering, and again when it comes back."));
        d.Text(T("One small ping per device each time, so the network hardly notices."), top: 2, muted: true);

        var list = new ListView
        {
            View = View.Details, CheckBoxes = true, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable, MultiSelect = false,
            Width = d.Width, Font = Theme.Base, HideSelection = true,
        };
        var line = TextRenderer.MeasureText("Wg", Theme.Base).Height;
        list.Height = line * 3 / 2 * 11 + line * 2;
        foreach (var (title, part) in new[] { (T("Type"), 0.26), (T("IP address"), 0.18), (T("Name"), 0.25), (T("Model"), 0.31) })
            list.Columns.Add(title, (int)((d.Width - SystemInformation.VerticalScrollBarWidth - S(6)) * part));
        foreach (var p in devices)
            list.Items.Add(new ListViewItem(new[] { T(p.Type), p.Ip, Bidi(p.Name), Bidi(p.Model) }) { Checked = p.On, Tag = p });

        // quick picks: tick every device of a kind
        var quick = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = true, MaximumSize = new Size(d.Width, 0), Padding = new Padding(0) };
        quick.Controls.Add(new Label { Text = T("Tick all:"), AutoSize = true, Margin = new Padding(0, S(7), S(4), 0) });
        void Quick(string text, Func<WatchPick, bool> which, bool on)
        {
            var b = new Button { Text = text, AutoSize = true, MinimumSize = new Size(0, S(28)), Margin = new Padding(0, S(2), S(6), S(2)), UseMnemonic = false };
            b.Click += (_, _) =>
            {
                list.BeginUpdate();
                foreach (ListViewItem i in list.Items) if (which((WatchPick)i.Tag!)) i.Checked = on;
                list.EndUpdate();
            };
            quick.Controls.Add(b);
        }
        foreach (var (text, group) in new[] { (T("Servers"), "server"), (T("Printers"), "printer"), (T("Cameras & NVR"), "camera"), (T("Network"), "network"), (T("Storage"), "storage") })
            if (devices.Any(p => p.Group == group)) Quick(text, p => p.Group == group, true);
        Quick(T("None"), _ => true, false);
        d.Add(quick, top: 12);
        d.Add(list, top: 6);

        var every = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = S(10) + TextRenderer.MeasureText(T("10 minutes"), Theme.Base).Width + SystemInformation.VerticalScrollBarWidth + S(16) };
        foreach (var i in WatchIntervals) every.Items.Add(i.Text);
        every.SelectedIndex = Array.FindIndex(WatchIntervals, i => i.Seconds >= seconds) is var k and >= 0 ? k : WatchIntervals.Length - 1;
        var row = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = false, Padding = new Padding(0) };
        row.Controls.Add(new Label { Text = T("Ping each one every"), AutoSize = true, Margin = new Padding(0, S(6), S(8), 0) });
        row.Controls.Add(every);
        d.Add(row, top: 12);
        var snd = d.Check(T("Play a sound when a device goes down or comes back"), sound, top: 6);
        d.Text(T("Watching goes on while NetFinder is open, also when it is minimized. The list is kept for next time."), top: 6, muted: true, small: true);
        var (ok, _) = d.Buttons(T("Watch"));
        void Count()
        {
            var n = list.CheckedItems.Count;
            ok.Text = n == 0 ? (devices.Any(p => p.On) ? T("Stop watching") : T("Watch")) : n == 1 ? T("Watch 1 device") : T($"Watch {n} devices");
        }
        list.ItemChecked += (_, _) => Count();
        Count();
        result = () => new WatchChoice(list.Items.Cast<ListViewItem>().Where(i => i.Checked).Select(i => (WatchPick)i.Tag!).ToList(),
            WatchIntervals[Math.Max(0, every.SelectedIndex)].Seconds, snd.Checked);
        return d;
    }

    /// <summary>Shows the About box. Returns true when the user pressed "Check for updates".</summary>
    public static bool About(IWin32Window owner)
    {
        using var f = new Form
        {
            Text = T("About ") + AppInfo.Name, FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent,
            MinimizeBox = false, MaximizeBox = false, ClientSize = new Size(420, 210), Font = Theme.Base, BackColor = Color.White, ShowInTaskbar = false,
        };
        var pic = new PictureBox { Image = Theme.Logo(), SizeMode = PictureBoxSizeMode.Zoom, Left = 20, Top = 20, Width = 96, Height = 96 };
        var name = new Label { Text = AppInfo.Name, Font = Theme.Title, Left = 132, Top = 26, AutoSize = true };
        var ver = new Label { Text = T("Version ") + AppInfo.Version, Left = 134, Top = 62, AutoSize = true, ForeColor = Theme.Muted };
        var tag = new Label { Text = AppInfo.Tagline, Left = 134, Top = 84, Width = 270, Height = 36 };
        var company = new Label { Text = "© " + AppInfo.Company, Left = 134, Top = 124, AutoSize = true, Font = Theme.Bold };
        var upd = new Button { Text = T("Check for updates"), DialogResult = DialogResult.Yes, Left = 20, Top = 168, Width = 150 };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Left = 325, Top = 168, Width = 75 };
        f.Controls.AddRange(new Control[] { pic, name, ver, tag, company, upd, ok });
        Ui.Direction(f);
        Ui.MirrorPositions(f);
        f.AcceptButton = ok;
        return f.ShowDialog(owner) == DialogResult.Yes;
    }
}

internal sealed class SettingsForm : Form
{
    private readonly Settings _s;
    private readonly TextBox _subnets = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = new Font("Consolas", 9.5f) };
    private readonly TextBox _ports = new() { Multiline = true, Dock = DockStyle.Fill, Font = new Font("Consolas", 9.5f) };
    private readonly CheckBox _learned = new() { Text = T("Also probe subnets heard on the wire"), AutoSize = true };
    private readonly CheckBox _linkLocal = new() { Text = T("Probe 169.254.x.x (slow, ~30 s)"), AutoSize = true };
    private readonly CheckBox _autoPorts = new() { Text = T("Check ports automatically for reachable devices"), AutoSize = true };
    private readonly NumericUpDown _fps = new() { Minimum = 100, Maximum = 20000, Increment = 500, Width = 90 };
    private readonly NumericUpDown _timeout = new() { Minimum = 100, Maximum = 5000, Increment = 100, Width = 90 };
    private readonly NumericUpDown _reachPrefix = new() { Minimum = 8, Maximum = 30, Width = 90 };
    private readonly TextBox _updateSource = new() { Width = 360, PlaceholderText = T("owner/repo  or  https://…/version.json") };
    private readonly CheckBox _checkUpdates = new() { Text = T("Check for updates automatically"), AutoSize = true };
    private readonly TextBox _snmp = new() { Width = 360, PlaceholderText = "public" };
    private readonly ComboBox _language = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 260 };
    private readonly List<L.Language> _languages = L.Available();

    /// <summary>True when the language was changed (the window is rebuilt in the new language after a restart).</summary>
    public bool LanguageChanged { get; private set; }

    public SettingsForm(Settings s, PluginRegistry plugins)
    {
        _s = s;
        Text = AppInfo.Name + T(" – Settings");
        Font = Theme.Base;
        Ui.Direction(this);
        Ui.Ltr(_subnets, _ports, _updateSource, _snmp);
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(660, 680);
        MinimumSize = new Size(560, 480);
        ShowInTaskbar = false;

        _subnets.Text = string.Join(Environment.NewLine, s.ProbeSubnets);
        _ports.Text = string.Join(", ", s.Ports);
        _learned.Checked = s.ProbeLearnedSubnets;
        _linkLocal.Checked = s.ProbeLinkLocal;
        _autoPorts.Checked = s.AutoCheckPorts;
        _fps.Value = Math.Clamp(s.FramesPerSecond, 100, 20000);
        _timeout.Value = Math.Clamp(s.PortTimeoutMs, 100, 5000);
        _reachPrefix.Value = Math.Clamp(s.ReachPrefix, 8, 30);
        _updateSource.Text = s.UpdateSource;
        _checkUpdates.Checked = s.CheckForUpdates;
        _snmp.Text = s.SnmpCommunities;
        foreach (var l in _languages) _language.Items.Add(l.Code == "en" || l.Name == l.EnglishName ? l.Name : $"{l.Name}  ({l.EnglishName})");
        _language.SelectedIndex = Math.Max(0, _languages.FindIndex(l => l.Code == L.Current.Code));

        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 2, RowCount = 13 };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 210));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 60));
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 20));
        for (var i = 0; i < 8; i++) grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        grid.Controls.Add(new Label { Text = "Language" + (L.Current.Code == "en" ? "" : " / " + T("Language")), AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        grid.Controls.Add(_language, 1, 0);
        grid.Controls.Add(new Label { Text = T("Other subnets to probe\n(one per line, e.g. 192.168.1.0/24)"), AutoSize = true }, 0, 1);
        grid.Controls.Add(_subnets, 1, 1);
        grid.Controls.Add(_learned, 1, 2);
        grid.Controls.Add(_linkLocal, 1, 3);
        grid.Controls.Add(new Label { Text = T("TCP ports to check"), AutoSize = true }, 0, 4);
        grid.Controls.Add(_ports, 1, 4);
        grid.Controls.Add(_autoPorts, 1, 5);
        grid.Controls.Add(new Label { Text = T("Probe speed (packets/second)"), AutoSize = true, Anchor = AnchorStyles.Left }, 0, 6);
        grid.Controls.Add(_fps, 1, 6);
        grid.Controls.Add(new Label { Text = T("Port timeout (ms)"), AutoSize = true, Anchor = AnchorStyles.Left }, 0, 7);
        grid.Controls.Add(_timeout, 1, 7);
        grid.Controls.Add(new Label { Text = T("Temporary IP prefix (/24 = 255.255.255.0)"), AutoSize = true, Anchor = AnchorStyles.Left }, 0, 8);
        grid.Controls.Add(_reachPrefix, 1, 8);
        grid.Controls.Add(new Label { Text = T("Update source"), AutoSize = true, Anchor = AnchorStyles.Left }, 0, 9);
        grid.Controls.Add(_updateSource, 1, 9);
        grid.Controls.Add(_checkUpdates, 1, 10);
        var pluginInfo = T($"Plugins loaded: {plugins.Analyzers.Count} analyzers, {plugins.Scanners.Count} scanners, {plugins.Classifiers.Count} classifiers, {plugins.ActionProviders.Count} action providers");
        grid.Controls.Add(new Label { Text = T("SNMP communities (models, ink levels, switch ports; comma between several)"), AutoSize = true, MaximumSize = new Size(200, 0), Anchor = AnchorStyles.Left }, 0, 11);
        grid.Controls.Add(_snmp, 1, 11);
        grid.Controls.Add(new Label { Text = pluginInfo, AutoSize = true, ForeColor = Theme.Muted }, 1, 12);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Height = 44, Padding = new Padding(8) };
        var ok = new Button { Text = T("Save"), Width = 90 };
        var cancel = new Button { Text = T("Cancel"), Width = 90, DialogResult = DialogResult.Cancel };
        var reset = new Button { Text = T("Defaults"), Width = 90 };
        var folder = new Button { Text = T("Plugins folder"), Width = 110 };
        ok.Click += (_, _) => Save();
        reset.Click += (_, _) => { var d = new Settings(); _subnets.Text = string.Join(Environment.NewLine, d.ProbeSubnets); _ports.Text = string.Join(", ", d.Ports); };
        folder.Click += (_, _) => { Directory.CreateDirectory(PluginRegistry.PluginFolder); Core.Actions.Launcher.Open(PluginRegistry.PluginFolder); };
        buttons.Controls.AddRange(new Control[] { cancel, ok, reset, folder });
        Controls.Add(grid);
        Controls.Add(buttons);
        AcceptButton = ok; CancelButton = cancel;
    }

    private void Save()
    {
        var subnets = new List<string>();
        foreach (var line in _subnets.Lines.Select(l => l.Trim()).Where(l => l.Length > 0))
        {
            if (!Core.Net.Subnet.TryParse(line, out var sn) || sn.Prefix < 16)
            {
                Ui.Box(this, T($"\"{line}\" is not a valid subnet (use e.g. 192.168.1.0/24, prefix /16 or longer)."), Text);
                return;
            }
            subnets.Add(sn.ToString());
        }
        var ports = _ports.Text.Split(new[] { ',', ' ', ';', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(p => int.TryParse(p, out var n) ? n : -1).Where(n => n is > 0 and < 65536).Distinct().ToList();
        _s.ProbeSubnets = subnets;
        _s.Ports = ports;
        _s.ProbeLearnedSubnets = _learned.Checked;
        _s.ProbeLinkLocal = _linkLocal.Checked;
        _s.AutoCheckPorts = _autoPorts.Checked;
        _s.FramesPerSecond = (int)_fps.Value;
        _s.PortTimeoutMs = (int)_timeout.Value;
        _s.ReachPrefix = (int)_reachPrefix.Value;
        _s.UpdateSource = _updateSource.Text.Trim();
        _s.CheckForUpdates = _checkUpdates.Checked;
        _s.SnmpCommunities = string.IsNullOrWhiteSpace(_snmp.Text) ? "public" : _snmp.Text.Trim();
        var lang = _languages[Math.Max(0, _language.SelectedIndex)].Code;
        LanguageChanged = lang != L.Current.Code;
        _s.Language = lang;
        Core.Update.UpdateChecker.Source = string.IsNullOrWhiteSpace(_s.UpdateSource) ? AppInfo.UpdateRepo : _s.UpdateSource;
        _s.Save();
        DialogResult = DialogResult.OK;
    }
}

/// <summary>
/// A small dialog that sizes itself to its text: every line wraps at a width that grows with the font, so nothing is cut
/// at any Windows scaling (125 %, 150 %…) or text size.
/// </summary>
internal sealed class AutoDialog : IDisposable
{
    public readonly Form Form;
    private readonly TableLayoutPanel _rows;
    /// <summary>The width text wraps at, in pixels.</summary>
    public readonly int Width;

    public AutoDialog(string title, int width)
    {
        Form = new Form
        {
            Text = title, FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.None,
            MinimizeBox = false, MaximizeBox = false, Font = Theme.Base, ShowInTaskbar = false, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
        };
        Ui.Direction(Form);
        // a line of the font is about 16 px at 100 %: the wrap width follows the real font size, whatever scales it
        var line = TextRenderer.MeasureText("Wg", Theme.Base).Height;
        Width = Math.Max(S(width), line * width / 16);
        var pad = S(16);
        Form.Padding = new Padding(pad, pad, pad, S(14));
        _rows = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Location = new Point(pad, pad), Margin = new Padding(0), Padding = new Padding(0) };
        Form.Controls.Add(_rows);
    }

    private int S(int v) => Form.LogicalToDeviceUnits(v);

    public T Add<T>(T c, int top = 0, int left = 0) where T : Control
    {
        c.Margin = new Padding(S(left), S(top), 0, 0);
        _rows.Controls.Add(c);
        return c;
    }

    public Label Text(string text, int top = 0, int left = 0, bool muted = false, bool bold = false, bool small = false) =>
        Add(new Label
        {
            Text = text, AutoSize = true, MaximumSize = new Size(Width - S(left), 0), UseMnemonic = false,
            ForeColor = muted ? Theme.Muted : SystemColors.ControlText, Font = bold ? Theme.Bold : small ? Theme.Small : Theme.Base,
        }, top, left);

    public CheckBox Check(string text, bool on, int top = 0, int left = 0) =>
        Add(new CheckBox { Text = text, AutoSize = true, Checked = on, UseMnemonic = false }, top, left);

    /// <summary>"User:" [box] rows; the boxes fill the rest of the width.</summary>
    public TableLayoutPanel Fields(int top, int left, params (string Label, Control Box)[] rows)
    {
        var labelW = rows.Max(r => TextRenderer.MeasureText(r.Label, Theme.Base).Width) + S(10);
        var t = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(0) };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, labelW));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        foreach (var (label, box) in rows)
        {
            t.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, S(4), 0, S(4)) });
            box.Width = Width - S(left) - labelW;
            box.Margin = new Padding(0, S(4), 0, S(4));
            t.Controls.Add(box);
        }
        return Add(t, top, left);
    }

    public (Button Ok, Button Cancel) Buttons(string okText)
    {
        var row = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = false, Anchor = AnchorStyles.Right,
        };
        Button B(string text, DialogResult r) => new()
        {
            Text = text, DialogResult = r, AutoSize = true, MinimumSize = new Size(S(90), S(30)), Padding = new Padding(S(8), 0, S(8), 0), Margin = new Padding(S(8), 0, 0, 0),
        };
        var cancel = B(T("Cancel"), DialogResult.Cancel);
        var ok = B(okText, DialogResult.OK);
        ok.Font = Theme.Bold;
        row.Controls.Add(cancel);
        row.Controls.Add(ok);
        Add(row, top: 20);
        row.Margin = new Padding(0, S(20), 0, 0);
        Form.AcceptButton = ok;
        Form.CancelButton = cancel;
        return (ok, cancel);
    }

    public bool Show(IWin32Window owner) => Form.ShowDialog(owner) == DialogResult.OK;
    public void Dispose() => Form.Dispose();
}

