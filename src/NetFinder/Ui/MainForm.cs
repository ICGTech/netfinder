using System.Collections.Concurrent;
using System.Net;
using System.Text;
using NetFinder.Core;
using NetFinder.Core.Actions;
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
    private readonly ToolStripButton _btnModels = new("Get models") { ToolTipText = "Ask every device for its model (also devices on other ranges, and Windows PCs with an admin login)" };
    private readonly ToolStripStatusLabel _stExport = new("Export results…") { IsLink = true, Visible = false, LinkBehavior = LinkBehavior.HoverUnderline, Margin = new Padding(8, 3, 8, 2) };
    private Dialogs.WindowsLogin? _winLogin; // memory only, never saved
    private bool _virtualSkipLogged;
    private CancellationTokenSource? _modelsCts;
    private readonly ToolStripLabel _lblCount = new("0 devices") { Font = new Font("Segoe UI Semibold", 11f), ForeColor = Theme.Accent, Alignment = ToolStripItemAlignment.Right, Margin = new Padding(12, 0, 4, 0) };

    // toolbar row 2: view
    private readonly ToolStrip _tools2 = new() { GripStyle = ToolStripGripStyle.Hidden, Padding = new Padding(8, 2, 8, 2), RenderMode = ToolStripRenderMode.System };
    private readonly ToolStripComboBox _cmbAdapter = new() { DropDownStyle = ComboBoxStyle.DropDownList, AutoSize = false, Width = 280 };
    private readonly ToolStripTextBox _txtFilter = new() { AutoSize = false, Width = 190, ToolTipText = "Filter by IP, name, vendor, type, MAC…" };
    private readonly ToolStripButton _chkOther = new("Other subnets only") { CheckOnClick = true };
    private readonly ToolStripButton _btnNpcap = new("Install Npcap") { Font = Theme.Bold, ForeColor = Color.FromArgb(0, 120, 212), ToolTipText = "Npcap lets the program see devices on OTHER IP ranges" };

    // banners
    private readonly Panel _banner = new() { Dock = DockStyle.Top, Height = 48, BackColor = Color.FromArgb(255, 244, 206), Visible = false, Padding = new Padding(12, 6, 12, 6) };
    private readonly Label _bannerText = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
    private readonly Panel _updateBanner = new() { Dock = DockStyle.Top, Height = 44, BackColor = Color.FromArgb(222, 236, 249), Visible = false, Padding = new Padding(12, 6, 12, 6) };
    private readonly Label _updateText = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = Theme.Bold, AutoEllipsis = true };
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
    private readonly SemaphoreSlim _portSem = new(8);
    private CancellationTokenSource? _scanCts;
    private readonly CancellationTokenSource _lifetime = new();
    private Device? _selected;
    private int _selectedRev = -1;
    private string _panelSig = "";
    private bool _cleared;
    private readonly bool _justUpdated;
    private readonly string? _whatsNew; // short list of changes, shown once after an update

    public MainForm(bool justUpdated = false)
    {
        _justUpdated = justUpdated;
        var lastVersion = _settings.LastVersion;
        if (justUpdated || (lastVersion != null && UpdateChecker.IsNewer(AppInfo.Version, lastVersion)))
            _whatsNew = Changelog.Text(Changelog.Since(lastVersion));
        if (lastVersion != AppInfo.Version) { _settings.LastVersion = AppInfo.Version; _settings.Save(); }
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
        Shown += (_, _) =>
        {
            _split.SplitterDistance = (int)(_split.Height * 0.55);
            if (_whatsNew != null)
                BeginInvoke(() => MessageBox.Show(this,
                    $"{AppInfo.Name} was updated to version {AppInfo.Version}." + (_whatsNew.Length > 0 ? "\n\nWhat's new:\n" + _whatsNew : ""),
                    AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information));
            else if (RunningFromZip())
                BeginInvoke(() => MessageBox.Show(this,
                    $"{AppInfo.Name} is running from INSIDE the zip file (Windows put it in a temporary folder).\n\n" +
                    "Updates cannot replace it there, so it will keep opening the old version.\n\n" +
                    "Close it, right-click the zip → \"Extract All\", and run NetFinder.exe from the extracted folder (e.g. Desktop or C:\\Tools).",
                    AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning));
        };
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
            _btnListen, _chkRepeat, _chkDeep, new ToolStripSeparator(), _btnModels,
        });
        _btnModels.Click += async (_, _) => { if (_modelsCts != null) _modelsCts.Cancel(); else await GetModelsForAllAsync(); };
        _tools.Items.Add(_lblCount);

        _txtFilter.TextChanged += (_, _) => ApplyFilter();
        _txtFilter.TextBox.PlaceholderText = "IP, name, vendor, type…";
        _chkOther.CheckedChanged += (_, _) => ApplyFilter();
        var btnClear = new ToolStripButton("Clear") { ToolTipText = "Clear the list" };
        btnClear.Click += (_, _) => { _engine.Store.Clear(); _engine.LearnedSubnets.Clear(); };
        var btnExport = new ToolStripButton("Export") { ToolTipText = "Save the list as Excel (.xlsx), CSV or an HTML report (print it to PDF)" };
        btnExport.Click += (_, _) => Export();
        var btnSettings = new ToolStripButton("Settings");
        btnSettings.Click += (_, _) => { using var f = new SettingsForm(_settings, _engine.Plugins); f.ShowDialog(this); };
        var btnAbout = new ToolStripButton("About");
        btnAbout.Click += async (_, _) => { if (Dialogs.About(this)) await CheckForUpdatesAsync(manual: true); };

        _tools2.Items.AddRange(new ToolStripItem[]
        {
            new ToolStripLabel("Adapter:"), _cmbAdapter, new ToolStripSeparator(),
            new ToolStripLabel("Filter:"), _txtFilter, _chkOther,
        });
        _btnNpcap.Click += async (_, _) => await NpcapButtonAsync();
        foreach (var b in new ToolStripItem[] { btnAbout, btnSettings, btnExport, btnClear, new ToolStripSeparator(), _btnNpcap })
        {
            b.Alignment = ToolStripItemAlignment.Right;
            _tools2.Items.Add(b);
        }
    }

    private void BuildBanners()
    {
        var install = new Button { Text = "Install Npcap", Dock = DockStyle.Right, Width = 120, BackColor = Theme.Accent, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = Theme.Bold };
        install.FlatAppearance.BorderSize = 0;
        install.Click += async (_, _) => await InstallNpcapAsync(t => install.Text = t, e => install.Enabled = e);
        var hide = new LinkLabel { Text = "Hide", Dock = DockStyle.Right, Width = 50, TextAlign = ContentAlignment.MiddleCenter };
        hide.LinkClicked += (_, _) => _banner.Visible = false;
        _banner.Controls.Add(_bannerText);
        _banner.Controls.Add(new Panel { Dock = DockStyle.Right, Width = 8 });
        _banner.Controls.Add(install);
        _banner.Controls.Add(hide);

        var updNow = new Button { Text = "Update now", Dock = DockStyle.Right, Width = 110, BackColor = Theme.Accent, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = Theme.Bold };
        updNow.FlatAppearance.BorderSize = 0;
        updNow.Click += async (_, _) => await InstallUpdateAsync(updNow);
        var skip = new LinkLabel { Text = "Later", Dock = DockStyle.Right, Width = 60, TextAlign = ContentAlignment.MiddleCenter };
        skip.LinkClicked += (_, _) => _updateBanner.Visible = false;
        _updateBanner.Controls.Add(_updateText);
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
        Col("Type", "Type", 190);
        Col("Ip", "IP address", 120);
        _grid.Columns.Add(new DataGridViewLinkColumn
        {
            Name = "Open", HeaderText = "Open", Width = 105, SortMode = DataGridViewColumnSortMode.Automatic, TrackVisitedState = false,
            LinkBehavior = LinkBehavior.HoverUnderline, LinkColor = Theme.Accent, ActiveLinkColor = Theme.Accent, VisitedLinkColor = Theme.Accent,
            ToolTipText = "Click to open the device (web page, Remote Desktop, SSH… whatever it has open)",
        });
        Col("Name", "Name", 180, fill: true);
        Col("Model", "Model", 190);
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
        _grid.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0 && _grid.Columns[e.ColumnIndex].Name != "Open") OpenPrimary(SelectedDevice()); };
        _grid.CellContentClick += (_, e) =>
        {
            if (e.RowIndex >= 0 && e.ColumnIndex >= 0 && _grid.Columns[e.ColumnIndex].Name == "Open" && _grid.Rows[e.RowIndex].Tag is Device d) OpenPrimary(d);
        };
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
        var g = e.Graphics;
        var size = Math.Clamp(e.CellBounds.Height - 8, 14, 40);
        var r = new Rectangle(e.CellBounds.X + 6, e.CellBounds.Y + (e.CellBounds.Height - size) / 2, size, size);
        Theme.DrawTypeIcon(g, r, type);
        var textRect = new Rectangle(r.Right + 7, e.CellBounds.Y, Math.Max(0, e.CellBounds.Right - r.Right - 9), e.CellBounds.Height);
        TextRenderer.DrawText(g, type, Theme.Base, textRect, type == DeviceTypes.Unknown ? Theme.Muted : Color.Black,
            TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
        e.Handled = true;
    }

    private ContextMenuStrip BuildContextMenu()
    {
        var m = new ContextMenuStrip();
        var open = new ToolStripMenuItem("Open") { Font = Theme.Bold, ToolTipText = "Web page, Remote Desktop, SSH… whatever the device has open" };
        open.Click += (_, _) => OpenPrimary(SelectedDevice());
        m.Items.Add(open);
        m.Items.Add("Open in browser (http)", null, (_, _) => OpenWeb(SelectedDevice(), "http"));
        m.Items.Add("Open in browser (https)", null, (_, _) => OpenWeb(SelectedDevice(), "https"));
        m.Items.Add("SSH", null, async (_, _) => { if (SelectedDevice() is { Ip: { } ip } d) await RunAction(d, new DeviceAction("Remote", "SSH", () => Launcher.Ssh(ip.ToString()))); });
        m.Items.Add("Telnet", null, async (_, _) => { if (SelectedDevice() is { Ip: { } ip } d) await RunAction(d, new DeviceAction("Remote", "Telnet", () => Launcher.Telnet(ip.ToString()))); });
        m.Items.Add(new ToolStripSeparator());
        m.Items.Add("Show cameras (NVR / DVR)…", Theme.TypeIcon(DeviceTypes.Nvr, 16, SystemColors.Menu), (_, _) => ShowCameras(SelectedDevice()));
        m.Items.Add("Make reachable (add temporary IP)", null, async (_, _) => { if (SelectedDevice() is { } d) await MakeReachableAsync(d); });
        m.Items.Add("Check open ports", null, async (_, _) => { if (SelectedDevice() is { } d) await CheckPortsAsync(d, force: true); });
        m.Items.Add("Get model", null, async (_, _) => { if (SelectedDevice() is { } d) await GetModelAsync(d); });
        m.Items.Add("Get model with Windows login…", null, async (_, _) => { if (SelectedDevice() is { } d) await GetWindowsModelAsync(d, askLogin: true); });
        m.Items.Add(new ToolStripSeparator());
        m.Items.Add("Copy IP", null, (_, _) => { if (SelectedDevice()?.Ip is { } ip) Clipboard.SetText(ip.ToString()); });
        m.Items.Add("Copy MAC", null, (_, _) => { if (SelectedDevice() is { Mac.Length: > 0 } d) Clipboard.SetText(d.Mac); });
        m.Items.Add(new ToolStripSeparator());
        m.Items.Add("Rename…", null, (_, _) => Rename(SelectedDevice()));
        var setType = new ToolStripMenuItem("Set type");
        setType.DropDownItems.Add("Automatic (detect)", null, (_, _) => SetType(SelectedDevice(), null));
        setType.DropDownItems.Add(new ToolStripSeparator());
        foreach (var t in DeviceTypes.All.Where(t => t != DeviceTypes.Unknown))
            setType.DropDownItems.Add(t, Theme.TypeIcon(t, 16, SystemColors.Menu), (_, _) => SetType(SelectedDevice(), t));
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
        _stExport.Click += (_, _) => Export();
        _status.Items.AddRange(new ToolStripItem[] { _stMode, new ToolStripSeparator(), _stCount, new ToolStripSeparator(), _stState, _stProgress, _stExport, _stCompany });
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

        var hasNpcap = Core.Net.WindowsNet.NpcapInstalled || _engine.CaptureDriver?.StartsWith("Npcap", StringComparison.OrdinalIgnoreCase) == true;
        _btnNpcap.Text = hasNpcap ? "Npcap ✓" : "Install Npcap";
        _btnNpcap.ForeColor = hasNpcap ? Theme.Good : Theme.Accent;
        _engine.Log($"Npcap installed: {hasNpcap}; capture: {(_engine.CaptureAvailable ? _engine.CaptureDriver : "none")}");
        if (!_engine.CaptureAvailable)
        {
            ShowNpcapBanner("Npcap is not installed. Devices on YOUR subnet are found with Windows ARP + ping, but devices on OTHER ranges (e.g. a camera still on 192.168.1.x) need Npcap. It is free; one click installs it.");
            _chkDeep.Enabled = false;
            _stMode.Text = "Basic mode (no Npcap)";
            _stMode.ForeColor = Theme.OtherSubnetText;
        }
        else if (!hasNpcap)
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

        if (_justUpdated) _engine.Log($"Updated to version {AppInfo.Version}");
        _btnListen.Checked = true; // starts listening (Npcap, or raw socket without it)
        BeginInvoke(new Action(async () => await ScanAsync()));
        if (_settings.CheckForUpdates && UpdateChecker.Enabled)
        {
            _updateTimer.Start();
            BeginInvoke(new Action(async () => { await Task.Delay(5000); await CheckForUpdatesAsync(manual: false); }));
        }
    }

    /// <summary>Explorer runs an .exe opened inside a .zip from %TEMP%\Temp1_xxx.zip\…, which is thrown away later.</summary>
    private static bool RunningFromZip()
    {
        var path = Environment.ProcessPath ?? "";
        var temp = Path.GetTempPath();
        return path.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
               (path.Contains(".zip", StringComparison.OrdinalIgnoreCase) || path.Contains("Temp1_", StringComparison.OrdinalIgnoreCase) ||
                path.Contains("Rar$", StringComparison.OrdinalIgnoreCase) || path.Contains("7z", StringComparison.OrdinalIgnoreCase));
    }

    private void ShowNpcapBanner(string text)
    {
        _bannerText.Text = text;
        _banner.Visible = true;
    }

    private async Task NpcapButtonAsync()
    {
        var hasNpcap = Core.Net.WindowsNet.NpcapInstalled || _engine.CaptureDriver?.StartsWith("Npcap", StringComparison.OrdinalIgnoreCase) == true;
        if (hasNpcap &&
            MessageBox.Show(this, $"Npcap is installed ({_engine.CaptureDriver ?? "driver not loaded"}).\n\nDownload and reinstall the latest Npcap anyway?",
                AppInfo.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Information) != DialogResult.Yes) return;
        await InstallNpcapAsync(t => _btnNpcap.Text = t, e => _btnNpcap.Enabled = e);
    }

    private async Task InstallNpcapAsync(Action<string> setText, Action<bool> setEnabled)
    {
        setEnabled(false);
        try
        {
            // 1) an installer the user already downloaded?
            string? installer = NpcapInstaller.FindLocalInstaller();
            if (installer != null && MessageBox.Show(this,
                    $"Found the Npcap installer {Path.GetFileName(installer)} in\n{Path.GetDirectoryName(installer)}\n\nInstall it?",
                    AppInfo.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                installer = null;

            // 2) download it from npcap.com / nmap.org
            if (installer == null)
            {
                setText("Downloading…");
                try { installer = await NpcapInstaller.DownloadAsync(new Progress<int>(p => setText($"Downloading {p}%")), _lifetime.Token); }
                catch (NpcapInstaller.UnreachableException ex)
                {
                    _engine.Log("Npcap download failed: " + ex.Message.Replace('\n', ' '));
                    // 3) offline / site blocked: let the user pick a file copied from elsewhere
                    installer = AskForNpcapInstaller(ex.Message);
                    if (installer == null) return;
                }
            }

            setText("Installing…");
            await NpcapInstaller.RunInstallerAsync(installer, _lifetime.Token);
            if (Core.Net.WindowsNet.NpcapInstalled)
            {
                MessageBox.Show(this, $"Npcap is installed. {AppInfo.Name} will restart to use it.", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                RestartApp();
                return;
            }
            MessageBox.Show(this, "Npcap was not installed (the setup was closed or failed).", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _engine.Log("Npcap install failed: " + ex.Message);
            MessageBox.Show(this, "Npcap could not be installed:\n\n" + ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally
        {
            if (!IsDisposed)
            {
                setText(Core.Net.WindowsNet.NpcapInstalled ? "Npcap ✓" : "Install Npcap");
                setEnabled(true);
            }
        }
    }

    /// <summary>Shown when npcap.com can't be reached. Returns a chosen installer file, or null.</summary>
    private string? AskForNpcapInstaller(string technical)
    {
        var choose = new TaskDialogButton("Choose installer file…");
        var open = new TaskDialogButton("Open npcap.com in browser");
        var page = new TaskDialogPage
        {
            Caption = AppInfo.Name,
            Icon = TaskDialogIcon.Warning,
            Heading = "This PC can't reach the Npcap website",
            Text = "npcap.com and nmap.org could not be reached: there is no internet, or the site is blocked on this network.\n\n" +
                   "Download the Npcap installer on another PC or phone from npcap.com (a file like npcap-1.80.exe), " +
                   "copy it to this PC (e.g. with a USB stick), then press \"Choose installer file…\".\n\n" +
                   $"Tip: if you put it in your Downloads folder, {AppInfo.Name} finds it by itself next time.",
            Buttons = { choose, open, TaskDialogButton.Cancel },
            Expander = new TaskDialogExpander(technical) { CollapsedButtonText = "Technical details" },
        };
        var result = TaskDialog.ShowDialog(this, page);
        if (result == open) { Core.Actions.Launcher.Open(NpcapInstaller.DownloadPage); return null; }
        if (result != choose) return null;
        using var dlg = new OpenFileDialog
        {
            Title = "Choose the Npcap installer",
            Filter = "Npcap installer (npcap-*.exe)|npcap*.exe|Programs (*.exe)|*.exe",
            InitialDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        };
        return dlg.ShowDialog(this) == DialogResult.OK ? dlg.FileName : null;
    }

    private void RestartApp()
    {
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true }); }
        catch { return; }
        Close();
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
            var summary = Changelog.OneLine(info.Notes);
            _updateText.Text = $"New version {info.Version} is available (you have {AppInfo.Version})" +
                (summary.Length > 0 ? ":  " + summary : ".") +
                (RunningFromZip() ? "  –  extract the zip first, updates can't work from inside it" : "");
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
            Close(); // the new version is already in place and started; it waits for us to exit
        }
        catch (Exception ex)
        {
            btn.Text = "Update now";
            btn.Enabled = true;
            UpdateChecker.Log("FAILED: " + ex);
            MessageBox.Show(this, "Update failed: " + ex.Message + "\n\nDetails: " + UpdateChecker.LogPath + "\n\nThe download page will open.", AppInfo.Name);
            Core.Actions.Launcher.Open(_update.PageUrl);
        }
    }

    // ───────────────────────────── scanning ─────────────────────────────

    private List<Adapter> SelectedAdapters()
    {
        if (_cmbAdapter.SelectedItem is Adapter a) return new List<Adapter> { a };
        var up = _engine.Adapters.Where(x => x.IsUp && (x.Addresses.Count > 0 || _engine.CaptureAvailable)).ToList();
        // host-only virtual networks (Hyper-V "Default Switch", VMware VMnet1/8…) hold only this PC's VMs: skip them unless picked by name
        var real = up.Where(x => !x.IsHostOnlyVirtual).ToList();
        if (real.Count == 0) return up;
        var skipped = up.Except(real).Select(x => x.FriendlyName).ToList();
        if (skipped.Count > 0 && !_virtualSkipLogged)
        {
            _virtualSkipLogged = true;
            _engine.Log($"Skipping virtual adapters {string.Join(", ", skipped)} (only this PC's virtual machines are there; pick one in the Adapter list to scan it)");
        }
        return real;
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
            _stExport.Visible = true;
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
            row.Cells["Type"].Value = d.IsSelf ? Theme.ThisPc : d.EffectiveType;
            row.Cells["Ip"].Value = d.Ip?.ToString() ?? "(unknown)";
            row.Cells["Open"].Value = PrimaryFor(d)?.Label ?? "";
            row.Cells["Name"].Value = d.DisplayName;
            row.Cells["Model"].Value = d.Model ?? "";
            row.Cells["Model"].ToolTipText = d.ModelSource != null ? "Model from " + d.ModelSource : "";
            row.Cells["Vendor"].Value = d.Vendor ?? "";
            row.Cells["Mac"].Value = d.Mac.Length > 0 ? d.Mac : "—";
            row.Cells["Net"].Value = NetText(d);
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
        lock (d) sig = string.Join("|", d.DisplayName, d.EffectiveType, d.TypeReason, d.Reachable, d.Mac, d.Ip, d.BehindNvr, d.Routed, d.Model, d.ModelSource, string.Join(",", d.OpenPorts),
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
        List<(int Port, string Info)> ports; DateTime? checkedAt; string? behindNvr, nvrChannel, nvrCount; bool nvrLike;
        (string Label, DeviceAction Action)? primary;
        lock (d)
        {
            behindNvr = d.BehindNvr;
            nvrChannel = d.Info.GetValueOrDefault("NVR channel");
            nvrCount = d.Info.GetValueOrDefault("NVR cameras");
            nvrLike = behindNvr == null && !d.IsSelf && d.Ip != null &&
                      (d.EffectiveType is DeviceTypes.Nvr or DeviceTypes.Camera || nvrCount != null || d.OpenPorts.Contains(37777) ||
                       System.Text.RegularExpressions.Regex.IsMatch(d.Vendor ?? "", "hikvision|dahua|hilook|annke|amcrest|lorex|uniview|tiandy|cp plus", System.Text.RegularExpressions.RegexOptions.IgnoreCase));
            primary = PrimaryFor(d);
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
        var iconType = self ? Theme.ThisPc : type;
        var badge = new Label { Text = "  " + iconType + "  ", AutoSize = true, BackColor = Theme.ForType(iconType), ForeColor = Color.White, Font = Theme.Bold, Padding = new Padding(2, 4, 2, 4), Margin = new Padding(0, 8, 10, 0) };
        head.Controls.Add(new PictureBox { Image = Theme.TypeIcon(iconType, 34), Size = new Size(34, 34), Margin = new Padding(0, 2, 10, 0) });
        head.Controls.Add(new Label { Text = title, Font = Theme.Title, AutoSize = true, Margin = new Padding(0, 0, 12, 0) });
        head.Controls.Add(badge);
        flow.Controls.Add(head);
        flow.Controls.Add(new Label { Text = sub, AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(2, 0, 0, 2) });
        if (!string.IsNullOrEmpty(typeWhy))
            flow.Controls.Add(new Label { Text = "Type detected from: " + typeWhy, AutoSize = true, ForeColor = Theme.Muted, Font = Theme.Small, Margin = new Padding(2, 0, 0, 8) });

        // reachability
        if (ip == null)
        {
            flow.Controls.Add(new Label
            {
                Text = "IP address not known yet: this device was only heard by its MAC address (LLDP / DHCP).\nPress Scan or wait a little; as soon as it has an IP, the buttons to open it appear here.",
                AutoSize = true, ForeColor = Theme.OtherSubnetText, Font = Theme.Bold, Margin = new Padding(2, 8, 0, 6),
            });
        }
        if (ip != null && !self)
        {
            var reach = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 4, 0, 6) };
            if (reachable)
            {
                bool routed; lock (d) routed = d.Routed;
                reach.Controls.Add(new Label { Text = routed ? "✔  Reachable through your router – you can open it directly." : "✔  Same subnet as this PC – you can open it directly.", AutoSize = true, ForeColor = Theme.Good, Font = Theme.Bold, Margin = new Padding(0, 6, 12, 0) });
                if (primary is { } pr)
                {
                    var openBtn = MakeButton("Open  " + pr.Label, Theme.Accent, Color.White);
                    openBtn.Font = Theme.Bold;
                    openBtn.Click += async (_, _) => await RunAction(d, pr.Action);
                    reach.Controls.Add(openBtn);
                }
            }
            else if (behindNvr != null)
            {
                reach.Controls.Add(new Label
                {
                    Text = $"Recorded by NVR {behindNvr}{ChannelSuffix(nvrChannel)}. " +
                           "Its IP is on the NVR's own camera network,\nso this PC can't open it directly: open it from the NVR's web page.",
                    AutoSize = true, ForeColor = Theme.OtherSubnetText, Font = Theme.Bold, Margin = new Padding(0, 6, 12, 0),
                });
                var nvrBtn = MakeButton("Open NVR web page", Theme.Accent, Color.White);
                nvrBtn.Click += async (_, _) => await OpenNvrAsync(behindNvr);
                reach.Controls.Add(nvrBtn);
                var tryBtn = MakeButton("Try a temporary IP", Color.White, Color.Black);
                new ToolTip().SetToolTip(tryBtn, "Works only if the camera is on the same cable/switch as this PC (not on the NVR's PoE ports)");
                tryBtn.Click += async (_, _) => await MakeReachableAsync(d);
                reach.Controls.Add(tryBtn);
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

        // NVR / DVR: list its cameras
        if (nvrLike)
        {
            flow.Controls.Add(new Label { Text = "NVR / DVR cameras", Font = Theme.Bold, AutoSize = true, Margin = new Padding(2, 10, 0, 2) });
            var nvrRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
            var cams = MakeButton(nvrCount != null ? $"Show cameras again ({nvrCount})" : "Show cameras on this NVR…", Color.White, Color.Black);
            cams.Image = Theme.TypeIcon(DeviceTypes.Camera, 18);
            cams.ImageAlign = ContentAlignment.MiddleLeft;
            cams.TextImageRelation = TextImageRelation.ImageBeforeText;
            cams.Click += (_, _) => ShowCameras(d);
            nvrRow.Controls.Add(cams);
            nvrRow.Controls.Add(new Label
            {
                Text = "Log in with the NVR's user and password to list its cameras: channel, IP, model, online/offline (Hikvision, Dahua and their rebrands).",
                AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(4, 10, 0, 0),
            });
            flow.Controls.Add(nvrRow);
        }

        // model
        if (ip != null || self)
        {
            string? model, modelSrc, serial; bool win; List<string> hw;
            lock (d)
            {
                model = d.Model; modelSrc = d.ModelSource; serial = d.Info.GetValueOrDefault("Serial number"); win = LooksWindows(d) || d.EffectiveType == DeviceTypes.WindowsPc;
                hw = new[] { ("CPU", ""), ("RAM", " RAM"), ("Disk", ""), ("Drive C:", ""), ("Graphics", ""), ("Windows", "") }
                    .Where(k => d.Info.ContainsKey(k.Item1))
                    .Select(k => k.Item1 == "Drive C:" ? "C: " + d.Info[k.Item1] : d.Info[k.Item1] + k.Item2).ToList();
            }
            flow.Controls.Add(new Label { Text = "Model", Font = Theme.Bold, AutoSize = true, Margin = new Padding(2, 10, 0, 2) });
            var modelRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
            modelRow.Controls.Add(new Label
            {
                Text = model != null ? $"{model}{(serial != null ? "   ·   S/N " + serial : "")}   (from {modelSrc})" : "Not known yet.",
                AutoSize = true, Font = model != null ? Theme.Bold : Theme.Base, ForeColor = model != null ? Color.Black : Theme.Muted, Margin = new Padding(2, 8, 12, 0),
            });
            if (!self)
            {
                var get = MakeButton("Get model", Color.White, Color.Black);
                new ToolTip().SetToolTip(get, "Ask the device (web page, UPnP, SNMP, ONVIF, IPP) – no password needed");
                get.Click += async (_, _) => await GetModelAsync(d);
                modelRow.Controls.Add(get);
            }
            if (win)
            {
                var wmi = MakeButton(self ? "Read this PC's model" : "Windows login…", Color.White, Color.Black);
                new ToolTip().SetToolTip(wmi, "Model, serial number, CPU, RAM, disks, graphics card and Windows version, read from Windows itself (needs an admin login on that PC)");
                wmi.Click += async (_, _) => await GetWindowsModelAsync(d, askLogin: !self);
                modelRow.Controls.Add(wmi);
            }
            flow.Controls.Add(modelRow);
            // what Windows told about the PC: CPU, RAM, disks, drive C:, graphics, Windows version
            if (hw.Count > 0)
                flow.Controls.Add(new Label
                {
                    Text = string.Join("\n", hw), AutoSize = true, ForeColor = Color.FromArgb(60, 60, 60), Margin = new Padding(2, 4, 0, 0),
                });
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
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP", 53 => "DNS", 80 => "HTTP", 81 or 82 or 88 => "HTTP", 110 => "POP3", 135 => "Windows RPC",
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
            Add("Model", d.Model == null ? null : d.Model + (d.ModelSource != null ? $"   (from {d.ModelSource})" : ""));
            Add("IP addresses", string.Join(", ", d.Ips));
            Add("MAC", d.Mac);
            Add("Vendor", d.Vendor);
            Add("Network", d.Ip == null ? null : d.Routed ? "Behind a router (reached by ping/TCP)" : d.Reachable ? "Same subnet as this PC" :
                d.BehindNvr != null ? $"On the camera network of NVR {d.BehindNvr}" : "Other subnet: " + Subnet.Of(d.Ip, 24));
            Add("Recorded by NVR", d.BehindNvr);
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
            string? nvr;
            lock (d) nvr = d.BehindNvr;
            if (nvr != null)
            {
                var c = MessageBox.Show(this,
                    $"{d.Ip} is recorded by NVR {nvr} and sits on the NVR's own camera network, so this PC can't open it directly.\n\n" +
                    "Yes  =  open the NVR's web page (you can see and set up the camera from there)\n" +
                    "No  =  try anyway with a temporary IP in its subnet",
                    AppInfo.Name, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
                if (c == DialogResult.Cancel) return;
                if (c == DialogResult.Yes) { await OpenNvrAsync(nvr); return; }
                if (!await MakeReachableAsync(d)) return;
                try { a.Execute(); }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
                return;
            }
            var r = MessageBox.Show(this,
                $"{d.Ip} is on another subnet, so this PC cannot talk to it yet.\n\nAdd a temporary IP in its subnet first? (It is removed when you close {AppInfo.Name}.)",
                AppInfo.Name, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (r == DialogResult.Cancel) return;
            if (r == DialogResult.Yes && !await MakeReachableAsync(d)) return;
        }
        try { a.Execute(); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    private void OpenWeb(Device? d, string scheme)
    {
        if (d?.Ip == null) return;
        var url = $"{scheme}://{d.Ip}/";
        _ = RunAction(d, new DeviceAction("Web", scheme, () => Launcher.Open(url)));
    }

    /// <summary>Best way to open a device (Open column, double-click, context menu).</summary>
    private static (string Label, DeviceAction Action)? PrimaryFor(Device d)
    {
        lock (d)
        {
            if (d.Ip == null || d.IsSelf) return null;
            if (d.BehindNvr != null && !d.Reachable)
            {
                var nvr = d.BehindNvr;
                return ("via NVR", new DeviceAction("NVR", "Open NVR web page", () => Launcher.Open($"http://{nvr}/")));
            }
            return BuiltInActions.Primary(d);
        }
    }

    private void OpenPrimary(Device? d)
    {
        if (d == null) return;
        if (PrimaryFor(d) is not { } p)
        {
            bool hasIp; lock (d) hasIp = d.Ip != null && !d.IsSelf;
            if (hasIp) { _ = CheckPortsAsync(d, force: true); _stState.Text = $"No open web/remote port known for {d.Ip}; checking its ports…"; }
            return;
        }
        if (p.Action.Group == "NVR") { string? nvr; lock (d) nvr = d.BehindNvr; if (nvr != null) _ = OpenNvrAsync(nvr); return; }
        _ = RunAction(d, p.Action);
    }

    /// <summary>Opens the NVR's best page (through RunAction, so an NVR on another subnet is made reachable first).</summary>
    private async Task OpenNvrAsync(string nvrIp)
    {
        if (IPAddress.TryParse(nvrIp, out var a) && _engine.Store.FindByIp(a) is { } nvr)
        {
            var p = PrimaryFor(nvr);
            await RunAction(nvr, p?.Action.Group == "Web" ? p.Value.Action : new DeviceAction("Web", "http", () => Launcher.Open($"http://{nvrIp}/")));
        }
        else
        {
            try { Launcher.Open($"http://{nvrIp}/"); } catch (Exception ex) { MessageBox.Show(this, ex.Message, AppInfo.Name); }
        }
    }

    private static string ChannelSuffix(string? nvrChannel)
    {
        var m = nvrChannel == null ? null : System.Text.RegularExpressions.Regex.Match(nvrChannel, @"channel (\d+)");
        return m is { Success: true } ? $" (channel {m.Groups[1].Value})" : "";
    }

    private static string NetText(Device d) => d.IsSelf ? "My subnet" : Core.Export.DeviceText.Network(d);

    /// <summary>"Show cameras": goes through RunAction so an NVR on another subnet is made reachable first.</summary>
    private void ShowCameras(Device? d)
    {
        if (d?.Ip == null) return;
        _ = RunAction(d, new DeviceAction("Tools", "Show cameras", () => ShowCamerasDialog(d)));
    }

    private void ShowCamerasDialog(Device d)
    {
        using var f = new NvrForm(_engine, d, dev => OpenPrimary(dev), url =>
        {
            if (IPAddress.TryParse(new Uri(url.Contains("://") ? url : "http://" + url).Host, out var ip) && _engine.Store.FindByIp(ip) is { } nvr)
                _ = RunAction(nvr, new DeviceAction("Web", url, () => Launcher.Open(url)));
            else
                try { Launcher.Open(url); } catch (Exception ex) { MessageBox.Show(this, ex.Message, AppInfo.Name); }
        });
        f.ShowDialog(this);
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

    private void Export()
    {
        using var dlg = new SaveFileDialog
        {
            Title = "Export the device list",
            Filter = "Excel workbook (*.xlsx)|*.xlsx|CSV – opens in Excel (*.csv)|*.csv|Report for browser / PDF (*.html)|*.html",
            FileName = $"{AppInfo.Name}-{DateTime.Now:yyyyMMdd-HHmm}",
            AddExtension = true,
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var path = dlg.FileName;
        var ext = Path.GetExtension(path).ToLowerInvariant();
        if (ext is not (".xlsx" or ".csv" or ".html" or ".htm")) path += dlg.FilterIndex switch { 2 => ".csv", 3 => ".html", _ => ".xlsx" };
        try
        {
            var devices = _engine.Store.All.Where(d => !_chkOther.Checked || !d.Reachable).ToList();
            Core.Export.Exporter.Save(path, devices, $"Network devices – {Environment.MachineName} – {DateTime.Now:yyyy-MM-dd HH:mm}");
            _stState.Text = $"Exported {devices.Count} devices to {path}";
            if (MessageBox.Show(this, $"Saved {devices.Count} devices to\n{path}\n\nOpen it now?", AppInfo.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                Launcher.Open(path);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Could not save the file: " + ex.Message + "\n\n(Is it open in Excel? Close it and try again.)", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    // ───────────────────────────── models ─────────────────────────────

    /// <summary>Asks one device for its model without a password (makes it reachable first if needed).</summary>
    private async Task GetModelAsync(Device d)
    {
        bool reachable, self; IPAddress? ip;
        lock (d) { reachable = d.Reachable; self = d.IsSelf; ip = d.Ip; }
        if (self) { await GetWindowsModelAsync(d, askLogin: false); return; }
        if (ip == null) return;
        if (!reachable)
        {
            string? nvr; lock (d) nvr = d.BehindNvr;
            if (nvr != null) { MessageBox.Show(this, $"{ip} is a camera on NVR {nvr}; its model comes from the NVR (Show cameras on the NVR).", AppInfo.Name); return; }
            if (MessageBox.Show(this, $"{ip} is on another subnet. Add a temporary IP in its subnet to ask it?", AppInfo.Name, MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            if (!await MakeReachableAsync(d)) return;
        }
        _stState.Text = $"Asking {ip} for its model…";
        await CheckPortsAsync(d, force: true);
        string? model, src;
        lock (d) { model = d.Model; src = d.ModelSource; }
        _stState.Text = model != null ? $"{ip}: {model}  (from {src})" :
            $"{ip} did not tell its model." + (LooksWindowsLocked(d) ? " It looks like a Windows PC: try \"Get model with Windows login\"." : "");
    }

    private static bool LooksWindowsLocked(Device d) { lock (d) return LooksWindows(d); }

    /// <summary>Windows PC (or probably one): worth asking with a Windows login. A PC maker's MAC alone is not enough.</summary>
    private static bool LooksWindows(Device d) =>
        d.IsSelf || d.Info.ContainsKey("Windows") || d.OpenPorts.Contains(135) || d.OpenPorts.Contains(3389) ||
        (d.OpenPorts.Contains(445) && d.EffectiveType is DeviceTypes.WindowsPc or DeviceTypes.Unknown or DeviceTypes.Vm) ||
        (d.EffectiveType is DeviceTypes.WindowsPc or DeviceTypes.Vm or DeviceTypes.Unknown && d.Info.GetValueOrDefault("TTL") == "128") ||
        (d.EffectiveType == DeviceTypes.WindowsPc && d.PortsCheckedAt != null && d.OpenPorts.Count == 0);

    /// <summary>The short (NetBIOS) domain name the Windows PCs on the list report ("ALMADA"), to spell the user name.</summary>
    private string? DomainHint() =>
        _engine.Store.All.Select(d => { lock (d) return d.Info.GetValueOrDefault("Workgroup / domain"); })
            .Where(v => v != null && !v.Contains('.') && !v.Equals("WORKGROUP", StringComparison.OrdinalIgnoreCase))
            .GroupBy(v => v!, StringComparer.OrdinalIgnoreCase).OrderByDescending(g => g.Count()).Select(g => g.Key).FirstOrDefault();

    /// <summary>PCs to check the login on first: domain members that answer SMB (the domain controller is ideal).</summary>
    private List<string> LoginCheckHosts(string user)
    {
        var dom = user.Contains('\\') ? user[..user.IndexOf('\\')] : user.Contains('@') ? user[(user.LastIndexOf('@') + 1)..] : null;
        var hint = DomainHint();
        return _engine.Store.All
            .Select(d => { lock (d) return (d, ip: d.Ip, ok: !d.IsSelf && d.Reachable && d.OpenPorts.Contains(445) && LooksWindows(d), name: d.Hostname ?? "", wg: d.Info.GetValueOrDefault("Workgroup / domain")); })
            .Where(x => x.ok && x.ip != null)
            .OrderByDescending(x => dom != null && dom.Contains('.') && x.name.EndsWith("." + dom, StringComparison.OrdinalIgnoreCase))
            .ThenByDescending(x => x.wg != null && (x.wg.Equals(hint, StringComparison.OrdinalIgnoreCase) || x.wg.Equals(dom, StringComparison.OrdinalIgnoreCase)))
            .ThenByDescending(x => x.d.OpenPorts.Contains(135))
            .Select(x => x.ip!.ToString()).Take(3).ToList();
    }

    /// <summary>Reads one PC's model from Windows (asks for a login when none is remembered yet).</summary>
    private async Task GetWindowsModelAsync(Device d, bool askLogin)
    {
        bool self; IPAddress? ip;
        lock (d) { self = d.IsSelf; ip = d.Ip; }
        if (ip == null && !self) return;
        if (!self && (askLogin || _winLogin == null))
        {
            var login = Dialogs.AskWindowsLogin(this, ip!.ToString(), _winLogin);
            if (login == null) return;
            _winLogin = login;
        }
        bool reachable; lock (d) reachable = d.Reachable || self;
        if (!reachable)
        {
            var r = MessageBox.Show(this, $"{ip} is on another subnet. Add a temporary IP in its subnet first?", AppInfo.Name, MessageBoxButtons.OKCancel, MessageBoxIcon.Question);
            if (r != DialogResult.OK || !await MakeReachableAsync(d)) return;
        }
        UseWaitCursor = true;
        var who = self ? "This PC" : ip!.ToString();
        _stState.Text = $"Reading the model of {(self ? "this PC" : who)} from Windows…";
        try
        {
            var session = new WindowsLoginSession(self ? null : _winLogin?.User, _winLogin?.Password, DomainHint(), _engine.Log);
            var res = await WindowsReader.ReadAsync(ip?.ToString() ?? ".", self, session, _lifetime.Token);
            _engine.Store.Touch(d, res.Info.ApplyTo);
            _engine.Log($"Windows {who}: {res.Info.Model ?? "model not reported"} (via {res.Info.Via}, login {res.Login}{(res.Note != null ? "; " + res.Note : "")})");
            _stState.Text = $"{who}: {res.Info.Model ?? "model not reported"}";
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            var kind = ex is WinReadException w ? w.Kind : WinFail.Other;
            _engine.Log($"Windows {who}: {ex.Message}");
            _stState.Text = "Could not read the Windows model: " + ex.Message.Split('\n')[0];
            MessageBox.Show(this, $"{who}: {ex.Message}.\n\n{WindowsAdvice(kind, single: true)}", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally { UseWaitCursor = false; }
    }

    private const string WmiFirewallGpo =
        "On the domain controller (Group Policy Management), in a policy linked to the PCs:\n" +
        "Computer Configuration › Policies › Windows Settings › Security Settings › Windows Defender Firewall with Advanced Security › " +
        "Inbound Rules › New Rule › Predefined: \"Windows Management Instrumentation (WMI)\" (or \"File and Printer Sharing\", port 445) › tick all › Allow the connection.\n" +
        "Then run gpupdate /force on the PCs (or restart them) and try again.";

    /// <summary>What to do about a failure, in plain words.</summary>
    private static string WindowsAdvice(WinFail kind, bool single) => kind switch
    {
        WinFail.Closed or WinFail.Blocked => (single
            ? "Its firewall blocks remote management. On that PC: Windows Defender Firewall › Allow an app › tick \"Windows Management Instrumentation (WMI)\" (Domain).\n\nFor many PCs at once: "
            : "To read them, allow WMI in their firewall once. ") + WmiFirewallGpo,
        WinFail.BadLogin => "Check the user name and password. In a domain, write the user as DOMAIN\\user (e.g. ALMADA\\administrator) or user@domain.local.",
        WinFail.AccessDenied or WinFail.NotAdmin => "Use an account that is administrator on that PC: a domain admin (DOMAIN\\user or user@domain.local), " +
            "or the PC's own Administrator (PCNAME\\Administrator; Windows 10/11 block other local admin accounts remotely).",
        _ => "Details are in the Log tab.",
    };

    /// <summary>
    /// "Get models": every device on the list, on every range. Devices on other subnets get a temporary IP in their range
    /// (one per range), then each device is asked without a password; Windows PCs also with a Windows login when one is given.
    /// </summary>
    private async Task GetModelsForAllAsync()
    {
        var all = _engine.Store.All.Where(d => { lock (d) return d.Ip != null || d.IsSelf; }).ToList();
        if (all.Count == 0) { MessageBox.Show(this, "The list is empty. Press Scan first.", AppInfo.Name); return; }
        int other, win;
        other = all.Count(d => { lock (d) return !d.Reachable && !d.IsSelf && d.BehindNvr == null; });
        win = all.Count(d => { lock (d) return LooksWindows(d); });
        var opt = Dialogs.AskModelsOptions(this, all.Count, other, win, _winLogin);
        if (opt == null) return;
        if (opt.Login != null) _winLogin = opt.Login;

        _modelsCts = new CancellationTokenSource();
        var ct = _modelsCts.Token;
        _btnModels.Text = "Stop models";
        _stProgress.Visible = true;
        int done = 0, found = 0, windowsOk = 0;
        var errors = new List<string>();
        var winFails = new Dictionary<WinFail, List<string>>();
        var session = opt.Login != null ? new WindowsLoginSession(opt.Login.User, opt.Login.Password, DomainHint(), _engine.Log) { AllowServiceStart = opt.StartRemoteRegistry } : null;
        var selfSession = new WindowsLoginSession(null, null, null, _engine.Log);
        if (session != null)
            _engine.Log("Get models: Windows login " + (session.User == null ? "= this PC's own login" : $"\"{session.User}\", trying {string.Join(", ", session.Spellings.Select(s => $"\"{s}\""))}"));
        try
        {
            // 1) one temporary IP per other range
            if (opt.OtherSubnets)
            {
                var groups = all.Where(d => { lock (d) return !d.Reachable && !d.IsSelf && d.BehindNvr == null && d.Ip != null; })
                    .GroupBy(d => { lock (d) return Subnet.Of(d.Ip!, _settings.ReachPrefix); }).ToList();
                foreach (var g in groups)
                {
                    ct.ThrowIfCancellationRequested();
                    _stState.Text = $"Adding a temporary IP for {g.Key}…";
                    var (ok, msg) = await _reach.MakeReachableAsync(g.First());
                    if (!ok) errors.Add($"{g.Key}: {msg.Split('\n')[0]}");
                }
            }

            // 2) check the Windows login once, on a domain PC, before using it on dozens of PCs
            if (session?.User != null)
            {
                _stState.Text = "Checking the Windows login…";
                foreach (var host in LoginCheckHosts(session.User))
                {
                    try { if (await session.CheckAsync(host, ct)) break; }
                    catch (WinReadException ex) { _engine.Log($"Windows login: could not check it on {host} ({ex.Message})"); }
                }
            }

            // 3) ask every reachable device (8 at a time)
            using var sem = new SemaphoreSlim(8);
            var targets = all.Where(d => { lock (d) return d.Reachable || d.IsSelf; }).ToList();
            await Task.WhenAll(targets.Select(async d =>
            {
                await sem.WaitAsync(ct);
                try
                {
                    bool self, isWin; IPAddress? ip;
                    lock (d) { self = d.IsSelf; ip = d.Ip; }
                    if (!self) await Task.Run(() => _engine.CheckPortsAsync(d, ct), ct);
                    lock (d) isWin = LooksWindows(d);
                    if (isWin && (self || session != null))
                    {
                        var who = self ? "This PC" : ip!.ToString();
                        try
                        {
                            var res = await WindowsReader.ReadAsync(ip?.ToString() ?? ".", self, self ? selfSession : session!, ct);
                            _engine.Store.Touch(d, res.Info.ApplyTo);
                            Interlocked.Increment(ref windowsOk);
                            _engine.Log($"Windows {who}: {res.Info.Model ?? "model not reported"} (via {res.Info.Via}, login {res.Login}{(res.Note != null ? "; " + res.Note : "")})");
                        }
                        catch (OperationCanceledException) { throw; }
                        catch (Exception ex)
                        {
                            var kind = ex is WinReadException w ? w.Kind : WinFail.Other;
                            lock (winFails) { if (!winFails.TryGetValue(kind, out var l)) winFails[kind] = l = new(); l.Add(who); }
                            // closed ports and "skipped" are summed up once at the end instead of one line per PC
                            if (kind != WinFail.Closed && !ex.Message.StartsWith("skipped")) _engine.Log($"Windows {who}: {ex.Message}");
                        }
                    }
                    lock (d) if (d.Model != null) Interlocked.Increment(ref found);
                }
                finally
                {
                    sem.Release();
                    var n = Interlocked.Increment(ref done);
                    if (!IsDisposed) _stState.Text = $"Getting models… {n}/{targets.Count}";
                }
            }));
            foreach (var e in errors) _engine.Log("Get models: " + e);
            var winFailed = winFails.Values.Sum(v => v.Count);
            _stState.Text = $"Models: {found} of {targets.Count} devices have a model" +
                            (windowsOk + winFailed > 0 ? $"  ·  Windows PCs: {windowsOk} read, {winFailed} not" : "") +
                            (errors.Count + winFailed > 0 ? "  ·  details in the Log tab" : "");
            _stExport.Visible = true;
            if (winFailed > 0) ShowWindowsSummary(windowsOk, winFails, session?.StopReason);
        }
        catch (OperationCanceledException) { _stState.Text = $"Get models stopped ({done} done)."; }
        finally
        {
            _modelsCts.Dispose(); _modelsCts = null;
            _btnModels.Text = "Get models";
            _stProgress.Visible = _scanCts != null;
        }
    }

    /// <summary>One clear summary of the Windows part of "Get models": what worked, what blocked it, and how to fix it.</summary>
    private void ShowWindowsSummary(int ok, Dictionary<WinFail, List<string>> fails, string? stopReason)
    {
        List<string> Get(params WinFail[] k) => k.SelectMany(x => fails.GetValueOrDefault(x) ?? new()).ToList();
        string Ips(List<string> l) => string.Join(", ", l.Take(12)) + (l.Count > 12 ? $" … (+{l.Count - 12})" : "");
        var closed = Get(WinFail.Closed);
        var blocked = Get(WinFail.Blocked);
        var denied = Get(WinFail.AccessDenied, WinFail.NotAdmin);
        var bad = Get(WinFail.BadLogin);
        var otherFail = Get(WinFail.Other);
        var lines = new List<string> { $"Windows PCs read: {ok}." };
        if (closed.Count > 0) lines.Add($"{closed.Count} PC(s) block every remote-management port (135 and 445 closed): {Ips(closed)}");
        if (blocked.Count > 0) lines.Add($"{blocked.Count} PC(s) answer, but their firewall blocks WMI: {Ips(blocked)}");
        if (denied.Count > 0) lines.Add($"{denied.Count} PC(s) refused the login (not an administrator there?): {Ips(denied)}");
        if (bad.Count > 0) lines.Add(stopReason ?? $"{bad.Count} PC(s): wrong user name or password: {Ips(bad)}");
        if (otherFail.Count > 0) lines.Add($"{otherFail.Count} PC(s) failed for another reason: {Ips(otherFail)}");
        foreach (var l in lines) _engine.Log("Windows summary: " + l);

        var advice = new List<string>();
        if (stopReason != null || bad.Count > 0) advice.Add(WindowsAdvice(WinFail.BadLogin, false));
        else if (denied.Count > 0) advice.Add(WindowsAdvice(WinFail.AccessDenied, false));
        if (closed.Count + blocked.Count > 0) advice.Add(WindowsAdvice(WinFail.Blocked, false));
        MessageBox.Show(this, string.Join("\n", lines) + "\n\n" + string.Join("\n\n", advice) + "\n\nThe result for each PC is in the Log tab.",
            AppInfo.Name + " – Windows models", MessageBoxButtons.OK, ok == 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
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
