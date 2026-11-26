using NetFinder.Core;
using NetFinder.Core.Model;
using NetFinder.Core.Plugins;

namespace NetFinder.Ui;

internal static class Dialogs
{
    public static string? Input(IWin32Window owner, string title, string prompt, string value)
    {
        using var f = new Form
        {
            Text = title, FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent,
            MinimizeBox = false, MaximizeBox = false, ClientSize = new Size(380, 120), Font = Theme.Base, ShowInTaskbar = false,
        };
        var lbl = new Label { Text = prompt, Left = 12, Top = 12, Width = 356 };
        var tb = new TextBox { Text = value, Left = 12, Top = 36, Width = 356 };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Left = 212, Top = 78, Width = 75 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Left = 293, Top = 78, Width = 75 };
        f.Controls.AddRange(new Control[] { lbl, tb, ok, cancel });
        f.AcceptButton = ok; f.CancelButton = cancel;
        return f.ShowDialog(owner) == DialogResult.OK ? tb.Text.Trim() : null;
    }

    /// <summary>Shows the About box. Returns true when the user pressed "Check for updates".</summary>
    public static bool About(IWin32Window owner)
    {
        using var f = new Form
        {
            Text = "About " + AppInfo.Name, FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent,
            MinimizeBox = false, MaximizeBox = false, ClientSize = new Size(420, 210), Font = Theme.Base, BackColor = Color.White, ShowInTaskbar = false,
        };
        var pic = new PictureBox { Image = Theme.Logo(), SizeMode = PictureBoxSizeMode.Zoom, Left = 20, Top = 20, Width = 96, Height = 96 };
        var name = new Label { Text = AppInfo.Name, Font = Theme.Title, Left = 132, Top = 26, AutoSize = true };
        var ver = new Label { Text = "Version " + AppInfo.Version, Left = 134, Top = 62, AutoSize = true, ForeColor = Theme.Muted };
        var tag = new Label { Text = AppInfo.Tagline, Left = 134, Top = 84, Width = 270, Height = 36 };
        var company = new Label { Text = "© " + AppInfo.Company, Left = 134, Top = 124, AutoSize = true, Font = Theme.Bold };
        var upd = new Button { Text = "Check for updates", DialogResult = DialogResult.Yes, Left = 20, Top = 168, Width = 150 };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Left = 325, Top = 168, Width = 75 };
        f.Controls.AddRange(new Control[] { pic, name, ver, tag, company, upd, ok });
        f.AcceptButton = ok;
        return f.ShowDialog(owner) == DialogResult.Yes;
    }
}

internal sealed class SettingsForm : Form
{
    private readonly Settings _s;
    private readonly TextBox _subnets = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = new Font("Consolas", 9.5f) };
    private readonly TextBox _ports = new() { Multiline = true, Dock = DockStyle.Fill, Font = new Font("Consolas", 9.5f) };
    private readonly CheckBox _learned = new() { Text = "Also probe subnets heard on the wire", AutoSize = true };
    private readonly CheckBox _linkLocal = new() { Text = "Probe 169.254.x.x (slow, ~30 s)", AutoSize = true };
    private readonly CheckBox _autoPorts = new() { Text = "Check ports automatically for reachable devices", AutoSize = true };
    private readonly NumericUpDown _fps = new() { Minimum = 100, Maximum = 20000, Increment = 500, Width = 90 };
    private readonly NumericUpDown _timeout = new() { Minimum = 100, Maximum = 5000, Increment = 100, Width = 90 };
    private readonly NumericUpDown _reachPrefix = new() { Minimum = 8, Maximum = 30, Width = 90 };
    private readonly TextBox _updateSource = new() { Width = 360, PlaceholderText = "owner/repo  or  https://…/version.json" };
    private readonly CheckBox _checkUpdates = new() { Text = "Check for updates automatically", AutoSize = true };

    public SettingsForm(Settings s, PluginRegistry plugins)
    {
        _s = s;
        Text = AppInfo.Name + " – Settings";
        Font = Theme.Base;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(660, 640);
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

        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 2, RowCount = 11 };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 210));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 60));
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 20));
        for (var i = 0; i < 7; i++) grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        grid.Controls.Add(new Label { Text = "Other subnets to probe\n(one per line, e.g. 192.168.1.0/24)", AutoSize = true }, 0, 0);
        grid.Controls.Add(_subnets, 1, 0);
        grid.Controls.Add(_learned, 1, 1);
        grid.Controls.Add(_linkLocal, 1, 2);
        grid.Controls.Add(new Label { Text = "TCP ports to check", AutoSize = true }, 0, 3);
        grid.Controls.Add(_ports, 1, 3);
        grid.Controls.Add(_autoPorts, 1, 4);
        grid.Controls.Add(new Label { Text = "Probe speed (packets/second)", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 5);
        grid.Controls.Add(_fps, 1, 5);
        grid.Controls.Add(new Label { Text = "Port timeout (ms)", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 6);
        grid.Controls.Add(_timeout, 1, 6);
        grid.Controls.Add(new Label { Text = "Temporary IP prefix (/24 = 255.255.255.0)", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 7);
        grid.Controls.Add(_reachPrefix, 1, 7);
        grid.Controls.Add(new Label { Text = "Update source", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 8);
        grid.Controls.Add(_updateSource, 1, 8);
        grid.Controls.Add(_checkUpdates, 1, 9);
        var pluginInfo = $"Plugins loaded: {plugins.Analyzers.Count} analyzers, {plugins.Scanners.Count} scanners, {plugins.Classifiers.Count} classifiers, {plugins.ActionProviders.Count} action providers";
        grid.Controls.Add(new Label { Text = pluginInfo, AutoSize = true, ForeColor = Theme.Muted }, 1, 10);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Height = 44, Padding = new Padding(8) };
        var ok = new Button { Text = "Save", Width = 90 };
        var cancel = new Button { Text = "Cancel", Width = 90, DialogResult = DialogResult.Cancel };
        var reset = new Button { Text = "Defaults", Width = 90 };
        var folder = new Button { Text = "Plugins folder", Width = 110 };
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
                MessageBox.Show(this, $"\"{line}\" is not a valid subnet (use e.g. 192.168.1.0/24, prefix /16 or longer).", Text);
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
        Core.Update.UpdateChecker.Source = string.IsNullOrWhiteSpace(_s.UpdateSource) ? AppInfo.UpdateRepo : _s.UpdateSource;
        _s.Save();
        DialogResult = DialogResult.OK;
    }
}
