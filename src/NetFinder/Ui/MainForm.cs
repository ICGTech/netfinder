using System.Collections.Concurrent;
using System.Net;
using System.Text;
using NetFinder.Core;
using NetFinder.Core.Model;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;
using NetFinder.Core.Update;

namespace NetFinder.Ui;

public sealed class MainForm : Form
{
    private readonly Settings _settings = Settings.Load();
    private readonly NetworkEngine _engine;
    private readonly ReachManager _reach;

    // toolbar row 1: actions
    private readonly ToolStrip _tools = new() { GripStyle = ToolStripGripStyle.Hidden, Padding = new Padding(8, 4, 8, 4), ImageScalingSize = new Size(20, 20), RenderMode = ToolStripRenderMode.System };
    private readonly ToolStripButton _btnScan = new("Scan") { Font = Theme.Bold, ToolTipText = "Sweep my subnet (or the Range) + probe other subnets + ask devices for their names" };
    private readonly ToolStripButton _btnStop = new("Stop") { Enabled = false };
    private readonly ToolStripButton _btnListen = new("Listening") { CheckOnClick = true, ToolTipText = "Passively catch any device that talks on the wire, on any subnet" };
    private readonly ToolStripButton _chkRepeat = new("Repeat scan") { CheckOnClick = true, ToolTipText = "Scan again every 2 minutes (catches phones that sleep on Wi-Fi)" };
    private readonly ToolStripButton _chkDeep = new("Deep scan 192.168.x.x") { CheckOnClick = true, ToolTipText = "Also probe all 65,536 addresses of 192.168.0.0/16 (~45 s, needs Npcap)" };
    private readonly ToolStripTextBox _txtRange = new() { AutoSize = false, Width = 230, ToolTipText = "Empty = automatic (my subnet).\nOr type ranges: 10.10.20.1-254, 10.10.0.0/16, 192.168.5.*" };
    private readonly ToolStripLabel _lblCount = new("0 devices") { Font = new Font("Segoe UI Semibold", 11f), ForeColor = Theme.Accent, Alignment = ToolStripItemAlignment.Right, Margin = new Padding(12, 0, 4, 0) };

    // toolbar row 2: view
    private readonly ToolStrip _tools2 = new() { GripStyle = ToolStripGripStyle.Hidden, Padding = new Padding(8, 2, 8, 2), RenderMode = ToolStripRenderMode.System };
    private readonly ToolStripComboBox _cmbAdapter = new() { DropDownStyle = ComboBoxStyle.DropDownList, AutoSize = false, Width = 280 };
    private readonly ToolStripTextBox _txtFilter = new() { AutoSize = false, Width = 190, ToolTipText = "Filter by IP, name, vendor, type, MAC…" };
    private readonly ToolStripButton _chkOther = new("Other subnets only") { CheckOnClick = true };

    // banners
    private readonly Panel _banner = new() { Dock = DockStyle.Top, Height = 48, BackColor = Color.FromArgb(255, 244, 206), Visible = false, Padding = new Padding(12, 6, 12, 6) };
    private readonly Label _bannerText = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
    private readonly Panel _updateBanner = new() { Dock = DockStyle.Top, Height = 44, BackColor = Color.FromArgb(222, 236, 249), Visible = false, Padding = new Padding(12, 6, 12, 6) };
    private readonly Label _updateText = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = Theme.Bold };
    private UpdateInfo? _update;

    // list + tabs
    private readonly SplitContainer _split = new() { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterWidth = 6 };
    private readonly DataGridView _grid = new();
    private readonly TabControl _tabs = new() { Dock = DockStyle.Fill, Padding = new Point(14, 5) };
    private readonly TabPage _tabDevice = new("Device");
    private readonly TabPage _tabDetails = new("All details");
    private readonly TabPage _tabLog = new("Log");
    private readonly Panel _devicePanel = new() { Dock = DockStyle.Fill, AutoScroll = true, BackColor = Color.White, Padding = new Padding(16, 12, 16, 12) };
    private readonly ListView _details = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable, BorderStyle = BorderStyle.None };
    private readonly TextBox _log = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 9f), BackColor = Color.White, BorderStyle = BorderStyle.None };

    // status
    private readonly StatusStrip _status = new() { SizingGrip = true };
    private readonly ToolStripStatusLabel _stCount = new("0 devices");
    private readonly ToolStripStatusLabel _stMode = new("") { Font = Theme.Bold };
    private readonly ToolStripStatusLabel _stState = new("") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly ToolStripProgressBar _stProgress = new() { Style = ProgressBarStyle.Marquee, Visible = false, Width = 120 };
    private readonly ToolStripStatusLabel _stCompany = new("© " + AppInfo.Company) { ForeColor = Theme.Muted };

    private readonly System.Windows.Forms.Timer _uiTimer = new() { Interval = 400 };
    private readonly System.Windows.Forms.Timer _repeatTimer = new() { Interval = 120_000 };
    private readonly System.Windows.Forms.Timer _updateTimer = new() { Interval = 12 * 3600 * 1000 };
    private readonly ConcurrentDictionary<string, Device> _dirty = new();
    private readonly ConcurrentQueue<Device> _removed = new();
    private readonly Dictionary<string, DataGridViewRow> _rows = new();
    private readonly ConcurrentQueue<string> _logQueue = new();
    private readonly ConcurrentDictionary<string, byte> _portsQueued = new();
    private readonly SemaphoreSlim _portSem = new(4);
    private CancellationTokenSource? _scanCts;
    private readonly CancellationTokenSource _lifetime = new();
    private Device? _selected;
    private int _selectedRev = -1;
    private string _panelSig = "";
    private bool _cleared;

    public MainForm()
    {
        Text = $"{AppInfo.Name} {AppInfo.Version}  –  {AppInfo.Company}";
        Font = Theme.Base;
        Icon = Theme.AppIcon();
        ClientSize = new Size(1280, 800);
        MinimumSize = new Size(960, 580);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.White;

        _engine = new NetworkEngine(_settings, typeof(MainForm).Assembly);
        if (!string.IsNullOrWhiteSpace(_settings.UpdateSource)) UpdateChecker.Source = _settings.UpdateSource;
        _engine.Store.Labels = UserLabels.Load();
        _reach = new ReachManager(_engine);

        BuildToolbar();
        BuildBanners();
        BuildGrid();
        BuildTabs();
        BuildStatus();

        _split.Panel1.Controls.Add(_grid);
        _split.Panel2.Controls.Add(_tabs);
        // Dock order: the control added LAST is docked FIRST (top-most).
        Controls.Add(_split);
        Controls.Add(_banner);
        Controls.Add(_updateBanner);
        Controls.Add(_tools2);
        Controls.Add(_tools);
        Controls.Add(_status);

        _engine.Store.Changed += d => _dirty[d.Key] = d;
        _engine.Store.Removed += d => _removed.Enqueue(d);
        _engine.Store.Cleared += () => _cleared = true;
        _engine.LogMessage += m => _logQueue.Enqueue(m);
        _uiTimer.Tick += (_, _) => FlushUi();
        _repeatTimer.Tick += async (_, _) => { if (_scanCts == null) await ScanAsync(); };
        _updateTimer.Tick += async (_, _) => await CheckForUpdatesAsync(manual: false);

        Load += (_, _) => Startup();
        Shown += (_, _) => _split.SplitterDistance = (int)(_split.Height * 0.55);
        FormClosing += OnClosing;
    }

    // ───────────────────────────── layout ─────────────────────────────

    private void BuildToolbar()
    {
        var logo = new ToolStripLabel(AppInfo.Name) { Font = new Font("Segoe UI Semibold", 11f), ForeColor = Theme.Brand, Image = Theme.Logo(), ImageScaling = ToolStripItemImageScaling.SizeToFit, Margin = new Padding(0, 0, 12, 0) };
        _btnScan.Click += async (_, _) => await ScanAsync();
        _btnStop.Click += (_, _) => _scanCts?.Cancel();
        _btnListen.CheckedChanged += (_, _) => ToggleListen(_btnListen.Checked);
        _chkRepeat.CheckedChanged += (_, _) => { if (_chkRepeat.Checked) _repeatTimer.Start(); else _repeatTimer.Stop(); };
        _chkDeep.CheckedChanged += (_, _) => _settings.DeepScan = _chkDeep.Checked;
        _txtRange.Text = _settings.ScanRanges;
        _txtRange.TextBox.PlaceholderText = "auto (my subnet)";
        _txtRange.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await ScanAsync(); } };

        _tools.Items.AddRange(new ToolStripItem[]
        {
            logo, new ToolStripSeparator(),
            _btnScan, _btnStop, new ToolStripSeparator(),
            new ToolStripLabel("Range:"), _txtRange, new ToolStripSeparator(),
            _btnListen, _chkRepeat, _chkDeep,
        });
        _tools.Items.Add(_lblCount);

        _txtFilter.TextChanged += (_, _) => ApplyFilter();
        _txtFilter.TextBox.PlaceholderText = "IP, name, vendor, type…";
        _chkOther.CheckedChanged += (_, _) => ApplyFilter();
        var btnClear = new ToolStripButton("Clear") { ToolTipText = "Clear the list" };
        btnClear.Click += (_, _) => { _engine.Store.Clear(); _engine.LearnedSubnets.Clear(); };
        var btnExport = new ToolStripButton("Export");
        btnExport.Click += (_, _) => ExportCsv();
        var btnSettings = new ToolStripButton("Settings");
        btnSettings.Click += (_, _) => { using var f = new SettingsForm(_settings, _engine.Plugins); f.ShowDialog(this); };
        var btnAbout = new ToolStripButton("About");
        btnAbout.Click += async (_, _) => { if (Dialogs.About(this)) await CheckForUpdatesAsync(manual: true); };

        _tools2.Items.AddRange(new ToolStripItem[]
        {
            new ToolStripLabel("Adapter:"), _cmbAdapter, new ToolStripSeparator(),
            new ToolStripLabel("Filter:"), _txtFilter, _chkOther,
        });
        foreach (var b in new ToolStripItem[] { btnAbout, btnSettings, btnExport, btnClear })
        {
            b.Alignment = ToolStripItemAlignment.Right;
            _tools2.Items.Add(b);
        }
    }

    private void BuildBanners()
    {
        var install = new Button { Text = "Install Npcap", Dock = DockStyle.Right, Width = 120, BackColor = Theme.Accent, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = Theme.Bold };
        install.FlatAppearance.BorderSize = 0;
        install.Click += async (_, _) => await InstallNpcapAsync(install);
        var hide = new LinkLabel { Text = "Hide", Dock = DockStyle.Right, Width = 50, TextAlign = ContentAlignment.MiddleCenter };
        hide.LinkClicked += (_, _) => _banner.Visible = false;
        _banner.Controls.Add(_bannerText);
        _banner.Controls.Add(new Panel { Dock = DockStyle.Right, Width = 8 });
        _banner.Controls.Add(install);
        _banner.Controls.Add(hide);

        var updNow = new Button { Text = "Update now", Dock = DockStyle.Right, Width = 110, BackColor = Theme.Accent, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = Theme.Bold };
        updNow.FlatAppearance.BorderSize = 0;
        updNow.Click += async (_, _) => await InstallUpdateAsync(updNow);
        var notes = new LinkLabel { Text = "What's new", Dock = DockStyle.Right, Width = 90, TextAlign = ContentAlignment.MiddleCenter };
        notes.LinkClicked += (_, _) => { if (_update != null) Core.Actions.Launcher.Open(_update.PageUrl); };
        var skip = new LinkLabel { Text = "Later", Dock = DockStyle.Right, Width = 60, TextAlign = ContentAlignment.MiddleCenter };
        skip.LinkClicked += (_, _) => _updateBanner.Visible = false;
        _updateBanner.Controls.Add(_updateText);
        _updateBanner.Controls.Add(notes);
        _updateBanner.Controls.Add(new Panel { Dock = DockStyle.Right, Width = 8 });
        _updateBanner.Controls.Add(updNow);
        _updateBanner.Controls.Add(skip);
    }

    private void BuildGrid()
    {
        _grid.Dock = DockStyle.Fill;
        _grid.ReadOnly = true;
        _grid.AllowUserToAddRows = false;
        _grid.AllowUserToDeleteRows = false;
        _grid.AllowUserToResizeRows = false;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.MultiSelect = false;
        _grid.BackgroundColor = Color.White;
        _grid.BorderStyle = BorderStyle.None;
        _grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        _grid.GridColor = Color.FromArgb(235, 235, 235);
        _grid.EnableHeadersVisualStyles = false;
        _grid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Panel;
        _grid.ColumnHeadersDefaultCellStyle.Font = Theme.Bold;
        _grid.ColumnHeadersDefaultCellStyle.Padding = new Padding(4, 6, 4, 6);
        _grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
        _grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
        _grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(204, 228, 247);
        _grid.DefaultCellStyle.SelectionForeColor = Color.Black;
        _grid.DefaultCellStyle.Padding = new Padding(4, 0, 4, 0);
        _grid.RowTemplate.Height = 28;
        _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None;
        typeof(DataGridView).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)?.SetValue(_grid, true);

        void Col(string name, string header, int width, bool fill = false)
        {
            var c = new DataGridViewTextBoxColumn { Name = name, HeaderText = header, Width = width, SortMode = DataGridViewColumnSortMode.Automatic };
            if (fill) { c.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill; c.MinimumWidth = 120; }
            _grid.Columns.Add(c);
        }
        Col("Type", "Type", 170);
        Col("Ip", "IP address", 120);
        Col("Name", "Name", 180, fill: true);
        Col("Vendor", "Vendor", 180);
        Col("Mac", "MAC", 130);
        Col("Net", "Network", 150);
        Col("Ports", "Open ports", 130);
        Col("Via", "Found via", 140);
        Col("Seen", "Last seen", 75);

        _grid.SortCompare += (_, e) =>
        {
            if (e.Column.Name == "Ip")
            {
                e.SortResult = IpKey(e.CellValue1).CompareTo(IpKey(e.CellValue2));
                e.Handled = true;
            }
        };
        _grid.CellPainting += PaintTypeCell;
        _grid.SelectionChanged += (_, _) => SelectDevice(SelectedDevice());
        _grid.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0) OpenWeb(SelectedDevice()); };
        _grid.ContextMenuStrip = BuildContextMenu();
        _grid.CellMouseDown += (_, e) =>
        {
            if (e.Button == MouseButtons.Right && e.RowIndex >= 0) { _grid.ClearSelection(); _grid.Rows[e.RowIndex].Selected = true; _grid.CurrentCell = _grid.Rows[e.RowIndex].Cells[1]; }
        };
    }

    private static long IpKey(object? v) =>
        v is string s && IPAddress.TryParse(s.Split(' ')[0], out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? Ip4.ToUInt(ip) : long.MaxValue;

    private void PaintTypeCell(object? sender, DataGridViewCellPaintingEventArgs e)
    {
        if (e.RowIndex < 0 || e.ColumnIndex != 0 || e.Graphics == null) return;
        e.PaintBackground(e.CellBounds, (e.State & DataGridViewElementStates.Selected) != 0);
        var type = e.FormattedValue?.ToString() ?? "";
        var color = Theme.ForType(type);
        var g = e.Graphics;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        var r = new Rectangle(e.CellBounds.X + 8, e.CellBounds.Y + (e.CellBounds.Height - 10) / 2, 10, 10);
        using (var b = new SolidBrush(color)) g.FillEllipse(b, r);
        var textRect = new Rectangle(r.Right + 6, e.CellBounds.Y, e.CellBounds.Width - 26, e.CellBounds.Height);
        TextRenderer.DrawText(g, type, Theme.Base, textRect, type == DeviceTypes.Unknown ? Theme.Muted : Color.Black,
            TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
        e.Handled = true;
    }

    private ContextMenuStrip BuildContextMenu()
    {
        var m = new ContextMenuStrip();
        m.Items.Add("Open in browser (http)", null, (_, _) => OpenWeb(SelectedDevice()));
        m.Items.Add("Make reachable (add temporary IP)", null, async (_, _) => { if (SelectedDevice() is { } d) await MakeReachableAsync(d); });
        m.Items.Add("Check open ports", null, async (_, _) => { if (SelectedDevice() is { } d) await CheckPortsAsync(d, force: true); });
        m.Items.Add(new ToolStripSeparator());
        m.Items.Add("Copy IP", null, (_, _) => { if (SelectedDevice()?.Ip is { } ip) Clipboard.SetText(ip.ToString()); });
        m.Items.Add("Copy MAC", null, (_, _) => { if (SelectedDevice() is { Mac.Length: > 0 } d) Clipboard.SetText(d.Mac); });
        m.Items.Add(new ToolStripSeparator());
        m.Items.Add("Rename…", null, (_, _) => Rename(SelectedDevice()));
        var setType = new ToolStripMenuItem("Set type");
        setType.DropDownItems.Add("Automatic (detect)", null, (_, _) => SetType(SelectedDevice(), null));
        setType.DropDownItems.Add(new ToolStripSeparator());
        foreach (var t in DeviceTypes.All.Where(t => t != DeviceTypes.Unknown))
            setType.DropDownItems.Add(t, null, (_, _) => SetType(SelectedDevice(), t));
        m.Items.Add(setType);
        m.Items.Add(new ToolStripSeparator());
        m.Items.Add("Remove from list", null, (_, _) => { if (SelectedDevice() is { } d) _engine.Store.Remove(d); });
        return m;
    }

    private void BuildTabs()
    {
        _tabDevice.Controls.Add(_devicePanel);
        _details.Columns.Add("Property", 220);
        _details.Columns.Add("Value", 700);
        _tabDetails.Controls.Add(_details);
        _tabLog.Controls.Add(_log);
        _tabs.TabPages.AddRange(new[] { _tabDevice, _tabDetails, _tabLog });
        ShowEmptyDevicePanel();
    }

    private void BuildStatus()
    {
        _status.Items.AddRange(new ToolStripItem[] { _stMode, new ToolStripSeparator(), _stCount, new ToolStripSeparator(), _stState, _stProgress, _stCompany });
    }

    // ───────────────────────────── startup ─────────────────────────────

    private void Startup()
    {
        _engine.LoadAdapters();
        _cmbAdapter.Items.Clear();
        _cmbAdapter.Items.Add("All connected adapters");
        foreach (var a in _engine.Adapters) _cmbAdapter.Items.Add(a);
        _cmbAdapter.SelectedIndex = 0;
        _uiTimer.Start();
        if (Environment.GetEnvironmentVariable("NETFINDER_DEMO") == "1") DemoData.Fill(_engine);

        if (!_engine.CaptureAvailable)
        {
            ShowNpcapBanner("Npcap is not installed. Devices on YOUR subnet are found with Windows ARP + ping, but devices on OTHER ranges (e.g. a camera still on 192.168.1.x) need Npcap. It is free; one click installs it.");
            _chkDeep.Enabled = false;
            _stMode.Text = "Basic mode (no Npcap)";
            _stMode.ForeColor = Theme.OtherSubnetText;
        }
        else if (_engine.OldWinPcap)
        {
            ShowNpcapBanner($"Old capture driver found ({_engine.CaptureDriver}). It does not work well on Wi-Fi and misses devices. Install Npcap to replace it.");
            _stMode.Text = $"Limited mode ({_engine.CaptureDriver})";
            _stMode.ForeColor = Theme.OtherSubnetText;
        }
        else
        {
            _stMode.Text = $"Full mode ({_engine.CaptureDriver})";
            _stMode.ForeColor = Theme.Good;
        }

        _btnListen.Checked = true; // starts listening (Npcap, or raw socket without it)
        BeginInvoke(new Action(async () => await ScanAsync()));
        if (_settings.CheckForUpdates && UpdateChecker.Enabled)
        {
            _updateTimer.Start();
            BeginInvoke(new Action(async () => { await Task.Delay(5000); await CheckForUpdatesAsync(manual: false); }));
        }
    }

    private void ShowNpcapBanner(string text)
    {
        _bannerText.Text = text;
        _banner.Visible = true;
    }

    private async Task InstallNpcapAsync(Button btn)
    {
        btn.Enabled = false;
        var old = btn.Text;
        try
        {
            btn.Text = "Downloading…";
            var progress = new Progress<int>(p => btn.Text = $"Downloading {p}%");
            btn.Text = "Installing…";
            await NpcapInstaller.DownloadAndRunAsync(progress, _lifetime.Token);
            if (Core.Net.WindowsNet.NpcapInstalled)
            {
                MessageBox.Show(this, $"Npcap is installed. {AppInfo.Name} will restart to use it.", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                Application.Restart();
                return;
            }
        }
        catch (Exception ex)
        {
            _engine.Log("Npcap download failed: " + ex.Message);
            MessageBox.Show(this, "Could not download Npcap automatically. The download page will open in your browser.\n\n" + ex.Message, AppInfo.Name);
            Core.Actions.Launcher.Open(NpcapInstaller.DownloadPage);
        }
        btn.Text = old;
        btn.Enabled = true;
    }

    // ───────────────────────────── updates ─────────────────────────────

    private async Task CheckForUpdatesAsync(bool manual)
    {
        if (!UpdateChecker.Enabled)
        {
            if (manual) MessageBox.Show(this, "No update source is set yet (Settings → Update source).", AppInfo.Name);
            return;
        }
        try
        {
            var info = await UpdateChecker.CheckAsync(_lifetime.Token);
            if (info == null)
            {
                if (manual) MessageBox.Show(this, $"You have the latest version ({AppInfo.Version}).", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            _update = info;
            _updateText.Text = $"A new version of {AppInfo.Name} is available: {info.Version}  (you have {AppInfo.Version})";
            _updateBanner.Visible = true;
        }
        catch (Exception ex)
        {
            if (manual) MessageBox.Show(this, "Could not check for updates: " + ex.Message, AppInfo.Name);
        }
    }

    private async Task InstallUpdateAsync(Button btn)
    {
        if (_update == null) return;
        btn.Enabled = false;
        try
        {
            await UpdateChecker.InstallAsync(_update, new Progress<int>(p => btn.Text = $"{p}%"), _lifetime.Token);
            Close(); // the update script waits for us to exit, replaces the .exe and starts the new version
        }
        catch (Exception ex)
        {
            btn.Text = "Update now";
            btn.Enabled = true;
            MessageBox.Show(this, "Update failed: " + ex.Message + "\n\nThe download page will open.", AppInfo.Name);
            Core.Actions.Launcher.Open(_update.PageUrl);
        }
    }

    // ───────────────────────────── scanning ─────────────────────────────

    private List<Adapter> SelectedAdapters()
    {
        if (_cmbAdapter.SelectedItem is Adapter a) return new List<Adapter> { a };
        return _engine.Adapters.Where(x => x.IsUp && (x.Addresses.Count > 0 || _engine.CaptureAvailable)).ToList();
    }

    private void ToggleListen(bool on)
    {
        try
        {
            if (on) _engine.StartListening(_engine.Adapters.Where(a => a.IsUp));
            else _engine.StopListening();
            _btnListen.Text = on ? "Listening" : "Listen";
            _stState.Text = on ? "Listening for devices…" : "Not listening";
        }
        catch (Exception ex)
        {
            _btnListen.Checked = false;
            _engine.Log("Listening failed: " + ex.Message);
        }
    }

    private async Task ScanAsync()
    {
        if (_scanCts != null) return;
        var rangeText = _txtRange.Text.Trim();
        if (!IpRange.TryParseList(rangeText, out _, out var err))
        {
            MessageBox.Show(this, err, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        if (rangeText != _settings.ScanRanges) { _settings.ScanRanges = rangeText; _settings.Save(); }

        _scanCts = new CancellationTokenSource();
        _btnScan.Enabled = false; _btnStop.Enabled = true; _stProgress.Visible = true;
        var progress = new Progress<string>(s => _stState.Text = s);
        try
        {
            await Task.Run(() => _engine.ScanAsync(SelectedAdapters(), _engine.Plugins.Scanners, progress, _scanCts.Token));
            _stState.Text = $"Scan finished at {DateTime.Now:HH:mm:ss}." + (_engine.Listening ? " Still listening for new devices…" : "");
        }
        catch (OperationCanceledException) { _stState.Text = "Scan stopped."; }
        catch (Exception ex) { _stState.Text = "Scan failed: " + ex.Message; }
        finally
        {
            _scanCts.Dispose(); _scanCts = null;
            _btnScan.Enabled = true; _btnStop.Enabled = false; _stProgress.Visible = false;
        }
    }

    // ───────────────────────────── UI refresh ─────────────────────────────

    private void FlushUi()
    {
        if (_cleared)
        {
            _cleared = false;
            _grid.Rows.Clear(); _rows.Clear(); _dirty.Clear(); _portsQueued.Clear();
            while (_removed.TryDequeue(out _)) { }
            SelectDevice(null);
        }
        var sb = new StringBuilder();
        while (_logQueue.TryDequeue(out var l)) sb.AppendLine(l);
        if (sb.Length > 0)
        {
            if (_log.TextLength > 200_000) _log.Clear();
            _log.AppendText(sb.ToString());
        }
        var changed = false;
        while (_removed.TryDequeue(out var gone))
        {
            _dirty.TryRemove(gone.Key, out _);
            if (_rows.Remove(gone.Key, out var row))
            {
                if (_selected == gone) SelectDevice(null);
                _grid.Rows.Remove(row);
                changed = true;
            }
        }
        if (_dirty.IsEmpty && !changed) { RefreshSelected(); return; }

        var sortCol = _grid.SortedColumn; var sortDir = _grid.SortOrder;
        foreach (var key in _dirty.Keys.ToList())
        {
            if (!_dirty.TryRemove(key, out var d)) continue;
            if (_engine.Store.Find(key) != d) continue;
            if (!_rows.TryGetValue(key, out var row))
            {
                var i = _grid.Rows.Add();
                row = _grid.Rows[i];
                row.Tag = d;
                _rows[key] = row;
            }
            FillRow(row, d);
            MaybeAutoCheckPorts(d);
        }
        if (sortCol != null && sortDir != SortOrder.None)
            _grid.Sort(sortCol, sortDir == SortOrder.Ascending ? System.ComponentModel.ListSortDirection.Ascending : System.ComponentModel.ListSortDirection.Descending);
        UpdateCounters();
        RefreshSelected();
    }

    private void UpdateCounters()
    {
        int total = 0, mine = 0, other = 0, routed = 0;
        foreach (var r in _rows.Values)
        {
            if (r.Tag is not Device d || d.IsSelf) continue;
            total++;
            lock (d)
            {
                if (d.Ip == null) continue;
                if (d.Routed) routed++;
                else if (d.Reachable) mine++;
                else other++;
            }
        }
        _lblCount.Text = $"Found: {total}";
        _lblCount.ToolTipText = $"{mine} on my subnet, {other} on other subnets, {routed} behind a router";
        _stCount.Text = $"{total} devices  ·  {mine} my subnet  ·  {other} other subnets" + (routed > 0 ? $"  ·  {routed} routed" : "");
    }

    private void FillRow(DataGridViewRow row, Device d)
    {
        lock (d)
        {
            row.Cells["Type"].Value = d.IsSelf ? "This PC" : d.EffectiveType;
            row.Cells["Ip"].Value = d.Ip?.ToString() ?? "(unknown)";
            row.Cells["Name"].Value = d.DisplayName;
            row.Cells["Vendor"].Value = d.Vendor ?? "";
            row.Cells["Mac"].Value = d.Mac.Length > 0 ? d.Mac : "—";
            row.Cells["Net"].Value = d.Ip == null ? "—" : d.Routed ? "Behind a router" : d.Reachable ? "My subnet" : $"Other: {Subnet.Of(d.Ip, 24)}";
            row.Cells["Ports"].Value = d.PortsCheckedAt == null ? (d.OpenPorts.Count > 0 ? string.Join(", ", d.OpenPorts) : "") : d.OpenPorts.Count == 0 ? "none" : string.Join(", ", d.OpenPorts);
            row.Cells["Via"].Value = string.Join(", ", d.Sources);
            row.Cells["Seen"].Value = d.LastSeen.ToString("HH:mm:ss");
            var otherNet = d.Ip != null && !d.Reachable;
            row.DefaultCellStyle.BackColor = otherNet ? Theme.OtherSubnet : Color.White;
            row.Cells["Net"].Style.ForeColor = otherNet ? Theme.OtherSubnetText : Theme.Good;
            row.Cells["Net"].Style.Font = otherNet ? Theme.Bold : Theme.Base;
        }
        SetVisible(row, MatchesFilter(row));
    }

    private void SetVisible(DataGridViewRow row, bool visible)
    {
        if (row.Visible == visible) return;
        if (!visible && _grid.CurrentRow == row) _grid.CurrentCell = null;
        row.Visible = visible;
    }

    private bool MatchesFilter(DataGridViewRow row)
    {
        if (row.Tag is not Device d) return true;
        if (_chkOther.Checked && (d.Reachable || d.Ip == null)) return false;
        var f = _txtFilter.Text.Trim();
        if (f.Length == 0) return true;
        return row.Cells.Cast<DataGridViewCell>().Any(c => c.Value?.ToString()?.Contains(f, StringComparison.OrdinalIgnoreCase) == true);
    }

    private void ApplyFilter()
    {
        foreach (var row in _rows.Values) SetVisible(row, MatchesFilter(row));
    }

    private void MaybeAutoCheckPorts(Device d)
    {
        if (!_settings.AutoCheckPorts || d.IsSelf) return;
        bool go;
        lock (d) go = d.Reachable && d.Ip != null && d.PortsCheckedAt == null;
        if (go && _portsQueued.TryAdd(d.Key, 0)) _ = CheckPortsAsync(d, force: false);
    }

    private async Task CheckPortsAsync(Device d, bool force)
    {
        if (force) _stState.Text = $"Checking ports of {d.Ip}…";
        await _portSem.WaitAsync();
        try { await Task.Run(() => _engine.CheckPortsAsync(d, _lifetime.Token)); }
        catch { }
        finally { _portSem.Release(); }
        if (force && !IsDisposed) _stState.Text = $"Ports of {d.Ip}: {(d.OpenPorts.Count == 0 ? "none open" : string.Join(", ", d.OpenPorts))}";
    }

    // ───────────────────────────── device tab ─────────────────────────────

    private Device? SelectedDevice() => _grid.SelectedRows.Count > 0 ? _grid.SelectedRows[0].Tag as Device : null;

    private void SelectDevice(Device? d)
    {
        _selected = d;
        _selectedRev = -1;
        _panelSig = "";
        RefreshSelected();
    }

    private void RefreshSelected()
    {
        var d = _selected;
        if (d == null) { if (_selectedRev != -2) { ShowEmptyDevicePanel(); _details.Items.Clear(); _selectedRev = -2; } return; }
        int rev;
        lock (d) rev = d.Revision;
        if (rev == _selectedRev) return;
        _selectedRev = rev;
        // Only rebuild when something visible changed (devices update on every packet).
        string sig;
        lock (d) sig = string.Join("|", d.DisplayName, d.EffectiveType, d.TypeReason, d.Reachable, d.Mac, string.Join(",", d.OpenPorts),
            string.Join(",", d.PortInfo.Values), d.PortsCheckedAt, d.Vendor, d.Info.Count, d.Services.Count, d.Sources.Count, d.TypeOverride);
        if (sig == _panelSig) return;
        _panelSig = sig;
        RenderDevicePanel(d);
        RenderDetails(d);
    }

    private void ShowEmptyDevicePanel()
    {
        _devicePanel.Controls.Clear();
        _devicePanel.Controls.Add(new Label
        {
            Text = "Select a device above to see how to open it.\n\nDevices with an orange background are on a different subnet from this PC.",
            Dock = DockStyle.Fill, ForeColor = Theme.Muted, TextAlign = ContentAlignment.MiddleCenter,
        });
    }

    private void RenderDevicePanel(Device d)
    {
        string title, sub, type, typeWhy; bool reachable, self; IPAddress? ip; List<DeviceAction> actions;
        List<(int Port, string Info)> ports; DateTime? checkedAt;
        lock (d)
        {
            ip = d.Ip;
            title = d.DisplayName.Length > 0 ? d.DisplayName : ip?.ToString() ?? d.Mac;
            sub = string.Join("   ·   ", new[] { ip?.ToString(), d.Mac.Length > 0 ? d.Mac : "MAC unknown (behind a router)", d.Vendor }.Where(s => !string.IsNullOrEmpty(s)));
            type = d.EffectiveType;
            typeWhy = d.TypeOverride != null ? "set by you" : d.TypeReason;
            reachable = d.Reachable; self = d.IsSelf;
            actions = _engine.Plugins.ActionProviders.SelectMany(p => { try { return p.GetActions(d).ToList(); } catch { return new List<DeviceAction>(); } }).ToList();
            ports = d.OpenPorts.Select(p => (p, d.PortInfo.TryGetValue(p, out var s) ? s : "")).ToList();
            checkedAt = d.PortsCheckedAt;
        }

        _devicePanel.SuspendLayout();
        _devicePanel.Controls.Clear();
        var flow = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Top };

        // header
        var head = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        var badge = new Label { Text = "  " + type + "  ", AutoSize = true, BackColor = Theme.ForType(type), ForeColor = Color.White, Font = Theme.Bold, Padding = new Padding(2, 4, 2, 4), Margin = new Padding(0, 8, 10, 0) };
        head.Controls.Add(new Label { Text = title, Font = Theme.Title, AutoSize = true, Margin = new Padding(0, 0, 12, 0) });
        head.Controls.Add(badge);
        flow.Controls.Add(head);
        flow.Controls.Add(new Label { Text = sub, AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(2, 0, 0, 2) });
        if (!string.IsNullOrEmpty(typeWhy))
            flow.Controls.Add(new Label { Text = "Type detected from: " + typeWhy, AutoSize = true, ForeColor = Theme.Muted, Font = Theme.Small, Margin = new Padding(2, 0, 0, 8) });

        // reachability
        if (ip != null && !self)
        {
            var reach = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 4, 0, 6) };
            if (reachable)
            {
                bool routed; lock (d) routed = d.Routed;
                reach.Controls.Add(new Label { Text = routed ? "✔  Reachable through your router – you can open it directly." : "✔  Same subnet as this PC – you can open it directly.", AutoSize = true, ForeColor = Theme.Good, Font = Theme.Bold, Margin = new Padding(0, 6, 12, 0) });
            }
            else
            {
                reach.Controls.Add(new Label
                {
                    Text = $"⚠  On another subnet ({Subnet.Of(ip, _settings.ReachPrefix)}). To open it, this PC needs a temporary IP in that subnet.",
                    AutoSize = true, ForeColor = Theme.OtherSubnetText, Font = Theme.Bold, Margin = new Padding(0, 6, 12, 0),
                });
                var btn = MakeButton("Make reachable", Theme.Accent, Color.White);
                btn.Click += async (_, _) => await MakeReachableAsync(d);
                reach.Controls.Add(btn);
            }
            flow.Controls.Add(reach);
        }

        // actions, grouped
        foreach (var g in actions.GroupBy(a => a.Group))
        {
            flow.Controls.Add(new Label { Text = g.Key, Font = Theme.Bold, AutoSize = true, Margin = new Padding(2, 10, 0, 2) });
            var row = new FlowLayoutPanel { AutoSize = true, WrapContents = true, MaximumSize = new Size(1400, 0), Margin = new Padding(0) };
            foreach (var a in g)
            {
                var b = MakeButton(a.Title, Color.White, Color.Black);
                if (a.Tooltip != null) new ToolTip().SetToolTip(b, a.Tooltip);
                b.Click += async (_, _) => await RunAction(d, a);
                row.Controls.Add(b);
            }
            if (g.Key == "Web")
            {
                var port = new TextBox { Width = 60, PlaceholderText = "port", Margin = new Padding(12, 6, 4, 0) };
                var go = MakeButton("Open port", Color.White, Color.Black);
                go.Click += async (_, _) =>
                {
                    if (!int.TryParse(port.Text, out var p) || p is < 1 or > 65535 || ip == null) return;
                    var scheme = p is 443 or 8443 or 4443 or 9443 ? "https" : "http";
                    await RunAction(d, new DeviceAction("Web", $"{scheme}://{ip}:{p}", () => Core.Actions.Launcher.Open($"{scheme}://{ip}:{p}/")));
                };
                row.Controls.Add(port);
                row.Controls.Add(go);
            }
            flow.Controls.Add(row);
        }

        // ports
        flow.Controls.Add(new Label { Text = "Open ports", Font = Theme.Bold, AutoSize = true, Margin = new Padding(2, 12, 0, 2) });
        var portLine = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        var portText = checkedAt == null
            ? (reachable ? "Not checked yet." : "Make the device reachable first, then check its ports.")
            : ports.Count == 0 ? $"No open ports found (checked {checkedAt:HH:mm:ss})."
            : string.Join("\n", ports.Select(p => $"{p.Port,-6} {PortName(p.Port)}{(p.Info.Length > 0 ? "   –   " + p.Info : "")}"));
        portLine.Controls.Add(new Label { Text = portText, AutoSize = true, Font = new Font("Consolas", 9.5f), Margin = new Padding(2, 4, 16, 0) });
        if (reachable && !self)
        {
            var chk = MakeButton("Check ports", Color.White, Color.Black);
            chk.Click += async (_, _) => await CheckPortsAsync(d, force: true);
            portLine.Controls.Add(chk);
        }
        flow.Controls.Add(portLine);

        // label + type
        var edit = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 14, 0, 0) };
        var rename = MakeButton("Rename…", Color.White, Color.Black);
        rename.Click += (_, _) => Rename(d);
        var typeBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 200, Margin = new Padding(12, 6, 0, 0) };
        typeBox.Items.Add("Type: automatic");
        typeBox.Items.AddRange(DeviceTypes.All.Where(t => t != DeviceTypes.Unknown).Cast<object>().ToArray());
        lock (d) typeBox.SelectedItem = d.TypeOverride ?? (object)"Type: automatic";
        typeBox.SelectedIndexChanged += (_, _) => SetType(d, typeBox.SelectedIndex == 0 ? null : typeBox.SelectedItem as string);
        edit.Controls.Add(rename);
        edit.Controls.Add(typeBox);
        flow.Controls.Add(edit);

        _devicePanel.Controls.Add(flow);
        _devicePanel.ResumeLayout();
    }

    private static string PortName(int p) => p switch
    {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP", 53 => "DNS", 80 => "HTTP", 81 or 82 or 88 => "HTTP", 110 => "POP3",
        139 => "NetBIOS", 143 => "IMAP", 161 => "SNMP", 443 => "HTTPS", 445 => "SMB (file sharing)", 502 => "Modbus", 515 => "LPD printer",
        554 => "RTSP (video)", 631 => "IPP printer", 1883 => "MQTT", 1900 => "UPnP", 3000 => "Web", 3306 => "MySQL", 3389 => "Remote Desktop",
        5000 or 5001 => "Web / NAS", 5060 => "SIP", 5432 => "PostgreSQL", 5900 => "VNC", 7547 => "TR-069", 8000 or 8001 => "Web",
        8008 or 8009 => "Cast", 8080 or 8081 or 8088 or 8888 or 8899 => "HTTP alt", 8291 => "Winbox", 8443 => "HTTPS alt", 8728 => "MikroTik API",
        9000 => "Web", 9100 => "Printer (RAW)", 37777 => "Dahua", 49152 => "UPnP", 62078 => "Apple sync",
        _ => "",
    };

    private static Button MakeButton(string text, Color back, Color fore)
    {
        var b = new Button
        {
            Text = text, AutoSize = true, BackColor = back, ForeColor = fore, FlatStyle = FlatStyle.Flat,
            Padding = new Padding(8, 3, 8, 3), Margin = new Padding(0, 4, 8, 4), Cursor = Cursors.Hand,
        };
        b.FlatAppearance.BorderColor = back == Color.White ? Color.FromArgb(200, 200, 200) : back;
        return b;
    }

    private void RenderDetails(Device d)
    {
        _details.BeginUpdate();
        _details.Items.Clear();
        void Add(string k, string? v) { if (!string.IsNullOrEmpty(v)) _details.Items.Add(new ListViewItem(new[] { k, v })); }
        lock (d)
        {
            Add("Type", d.EffectiveType + (d.TypeOverride != null ? " (set by you)" : ""));
            Add("Detected from", d.TypeReason);
            Add("Name (yours)", d.CustomName);
            Add("Hostname", d.Hostname);
            Add("Model", d.Model);
            Add("IP addresses", string.Join(", ", d.Ips));
            Add("MAC", d.Mac);
            Add("Vendor", d.Vendor);
            Add("Network", d.Ip == null ? null : d.Routed ? "Behind a router (reached by ping/TCP)" : d.Reachable ? "Same subnet as this PC" : "Other subnet: " + Subnet.Of(d.Ip, 24));
            Add("Found via", string.Join(", ", d.Sources));
            Add("Adapter", _engine.AdapterById(d.AdapterId)?.FriendlyName);
            Add("First seen", d.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss"));
            Add("Last seen", d.LastSeen.ToString("yyyy-MM-dd HH:mm:ss"));
            Add("Open ports", string.Join(", ", d.OpenPorts));
            foreach (var kv in d.PortInfo) Add($"Port {kv.Key}", kv.Value);
            Add("Services (mDNS)", string.Join(", ", d.Services));
            foreach (var kv in d.Info) Add(kv.Key, kv.Value);
        }
        _details.EndUpdate();
    }

    // ───────────────────────────── commands ─────────────────────────────

    private async Task RunAction(Device d, DeviceAction a)
    {
        bool reachable;
        lock (d) reachable = d.Reachable || d.IsSelf;
        if (!reachable && a.Group is "Web" or "Remote" or "Tools")
        {
            var r = MessageBox.Show(this,
                $"{d.Ip} is on another subnet, so this PC cannot talk to it yet.\n\nAdd a temporary IP in its subnet first? (It is removed when you close {AppInfo.Name}.)",
                AppInfo.Name, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (r == DialogResult.Cancel) return;
            if (r == DialogResult.Yes && !await MakeReachableAsync(d)) return;
        }
        try { a.Execute(); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    private void OpenWeb(Device? d)
    {
        if (d?.Ip == null) return;
        _ = RunAction(d, new DeviceAction("Web", "http", () => Core.Actions.Launcher.Open($"http://{d.Ip}/")));
    }

    private async Task<bool> MakeReachableAsync(Device d)
    {
        UseWaitCursor = true;
        _stState.Text = $"Adding a temporary IP to reach {d.Ip}…";
        try
        {
            var (ok, msg) = await _reach.MakeReachableAsync(d);
            _stState.Text = msg.Split('\n')[0];
            if (!ok) { MessageBox.Show(this, msg, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); return false; }
            _ = CheckPortsAsync(d, force: true);
            return true;
        }
        finally { UseWaitCursor = false; }
    }

    private void Rename(Device? d)
    {
        if (d == null) return;
        string current;
        lock (d) current = d.CustomName ?? d.Hostname ?? "";
        var name = Dialogs.Input(this, "Rename device", $"Name for {d.Ip}{(d.Mac.Length > 0 ? $" ({d.Mac})" : "")}:", current);
        if (name == null) return;
        _engine.Store.Touch(d, x => x.CustomName = name.Length == 0 ? null : name);
        lock (d) _engine.Store.Labels.Set(d);
    }

    private void SetType(Device? d, string? type)
    {
        if (d == null) return;
        string? cur;
        lock (d) cur = d.TypeOverride;
        if (cur == type) return;
        _engine.Store.Touch(d, x => x.TypeOverride = type);
        lock (d) _engine.Store.Labels.Set(d);
    }

    private void ExportCsv()
    {
        using var dlg = new SaveFileDialog { Filter = "CSV file|*.csv", FileName = $"{AppInfo.Name}-{DateTime.Now:yyyyMMdd-HHmm}.csv" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var sb = new StringBuilder();
        sb.AppendLine("Type,IP,All IPs,Name,Hostname,Model,Vendor,MAC,Network,Open ports,Found via,First seen,Last seen");
        static string Q(string? s) => "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";
        foreach (var d in _engine.Store.All.OrderBy(x => x.Ip == null ? long.MaxValue : (long)Ip4.ToUInt(x.Ip)))
            lock (d)
                sb.AppendLine(string.Join(",", Q(d.EffectiveType), Q(d.Ip?.ToString()), Q(string.Join(" ", d.Ips)), Q(d.CustomName), Q(d.Hostname), Q(d.Model),
                    Q(d.Vendor), Q(d.Mac), Q(d.Reachable ? "My subnet" : "Other subnet"), Q(string.Join(" ", d.OpenPorts)), Q(string.Join(" ", d.Sources)),
                    Q(d.FirstSeen.ToString("s")), Q(d.LastSeen.ToString("s"))));
        File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
        _stState.Text = "Exported to " + dlg.FileName;
    }

    private void OnClosing(object? sender, FormClosingEventArgs e)
    {
        _lifetime.Cancel();
        _scanCts?.Cancel();
        _uiTimer.Stop();
        _repeatTimer.Stop();
        _updateTimer.Stop();
        if (_reach.Added.Count > 0) _reach.RemoveAllBlocking();
        _engine.Dispose();
    }
}
