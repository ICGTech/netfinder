using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using NetFinder.Core;
using NetFinder.Core.Classifiers;
using NetFinder.Core.Actions;
using NetFinder.Core.Model;
using NetFinder.Core.Monitoring;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;
using NetFinder.Core.Update;
using static NetFinder.Core.Text.L;

namespace NetFinder.Ui;

public sealed class MainForm : Form
{
    private readonly Settings _settings = Settings.Load();
    private readonly NetworkEngine _engine;
    private readonly ReachManager _reach;
    private readonly ChromeRenderer _renderer = new();

    // header: one row
    private readonly ToolStrip _tools = new() { GripStyle = ToolStripGripStyle.Hidden, CanOverflow = false, ImageScalingSize = new Size(20, 20) };
    private readonly ToolStripButton _btnScan = new(T("▶  Scan")) { Tag = "primary", Font = Theme.HeaderBold, ToolTipText = T("Sweep my subnet (or the Range) + probe other subnets + ask devices for their names") };
    private readonly ToolStripButton _btnStop = new(T("Stop")) { Enabled = false, Visible = false, Font = Theme.Header };
    private readonly ToolStripButton _btnListen = new(T("Listening")) { Tag = "pill", CheckOnClick = true, Font = Theme.Bold, ToolTipText = T("Passively catch any device that talks on the wire, on any subnet") };
    // scan options, next to Scan (on/off buttons with a check box)
    private readonly ToolStripButton _chkRepeat = new(T("Repeat")) { Tag = "toggle", CheckOnClick = true, Font = Theme.Header,
        ToolTipText = T("Repeat the scan every 2 minutes: new devices are added and the list is not emptied (catches phones that sleep on Wi-Fi)") };
    private readonly ToolStripButton _chkDeep = new(T("Deep scan")) { Tag = "toggle", CheckOnClick = true, Font = Theme.Header,
        ToolTipText = T("Deep scan: also look through all 65,536 addresses of 192.168.x.x for devices left on another range (about 45 s more per scan, needs Npcap)") };
    private readonly ToolStripMenuItem _chkDark = new(T("Dark mode")) { CheckOnClick = true };
    private readonly ToolStripDropDownButton _menu = new("☰") { ShowDropDownArrow = false, Font = Theme.HeaderBold, ToolTipText = T("Repeat scan, deep scan, dark mode, settings…") };
    private readonly InputBox _rangeBox = new(210);
    private readonly InputBox _filterBox = new(250) { SearchIcon = true };
    private readonly ToolStripControlHost _rangeHost;
    private readonly int _rangeWidth;
    private readonly BrandItem _brand = new();
    private readonly ToolStripLabel _rangeLabel = new(T("Range")) { Tag = "muted", Font = Theme.Header };
    /// <summary>Top of the side menu: the filter box (it was in the header, which now holds the scan options).</summary>
    private readonly Panel _navTop = new() { Dock = DockStyle.Top };
    private TextBox _txtRange => _rangeBox.Box;
    private TextBox _txtFilter => _filterBox.Box;
    private readonly ToolStripButton _btnModels = new(T("Get models")) { Font = Theme.Header, ToolTipText = T("Ask every device for its model (also devices on other ranges, and Windows PCs with an admin login)") };
    private readonly ToolStripStatusLabel _stExport = new(T("Export results…")) { IsLink = true, Visible = false, LinkBehavior = LinkBehavior.HoverUnderline, Margin = new Padding(8, 3, 8, 2) };
    private Dialogs.WindowsLogin? _winLogin; // memory only, never saved
    private readonly ToolStripDropDownButton _export = new(T("Export")) { ShowDropDownArrow = false, Font = Theme.Header, ToolTipText = T("Save the list shown as Excel, PDF, CSV or a web page") };

    // watch devices (ping monitor)
    private readonly Watcher _watcher;
    private readonly List<WatchItem> _watchList;
    private readonly ConcurrentQueue<(WatchState State, Health Before)> _watchEvents = new();
    private volatile bool _watchChecked;
    private NotifyIcon? _tray;
    private string? _trayIp;
    private readonly RoundButton _watchPick = new(T("Pick devices to watch…"), false) { Visible = false };
    private bool _virtualSkipLogged;
    private CancellationTokenSource? _modelsCts;

    // banners
    private readonly Panel _banner = new() { Dock = DockStyle.Top, Height = 48, Visible = false, Padding = new Padding(12, 6, 12, 6) };
    private readonly Label _bannerText = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
    private readonly Panel _updateBanner = new() { Dock = DockStyle.Top, Height = 44, Visible = false, Padding = new Padding(12, 6, 12, 6) };
    private readonly Label _updateText = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Font = Theme.Bold, AutoEllipsis = true };
    private readonly List<Button> _bannerButtons = new();
    private readonly List<LinkLabel> _bannerLinks = new();
    private UpdateInfo? _update;

    // side menu
    private readonly Panel _navHost = new() { Dock = DockStyle.Left };
    private readonly NavList _nav = new() { Dock = DockStyle.Fill };
    private readonly FlowLayoutPanel _navBottom = new() { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink };
    private readonly Label _adapterLabel = new() { Text = T("ADAPTER"), AutoSize = true, Font = Theme.Section };
    private readonly DropPicker _cmbAdapter = new();
    private readonly InfoCard _npcapCard = new();

    // list
    private readonly SplitContainer _split = new() { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, FixedPanel = FixedPanel.Panel2, SplitterWidth = 1 };
    private readonly FlowLayoutPanel _titleRow = new() { Dock = DockStyle.Top, AutoSize = true, WrapContents = false };
    private readonly Label _title = new() { Text = T("All devices"), AutoSize = true, Font = Theme.Heading, Margin = new Padding(0), UseMnemonic = false };
    private readonly Label _summary = new() { AutoSize = true, Font = Theme.Header };
    private readonly Panel _gridCard = new() { Dock = DockStyle.Fill, Padding = new Padding(1) };
    private readonly DataGridView _grid = new();
    private DateTime? _lastScan;

    // details pane
    private readonly DetailsHeader _detailsHead = new() { Dock = DockStyle.Top };
    private readonly SegmentedTabs _tabs = new(T("Overview"), T("All details"), T("Log")) { Dock = DockStyle.Top };
    private readonly Panel _tabBody = new() { Dock = DockStyle.Fill };
    private readonly Panel _devicePanel = new() { Dock = DockStyle.Fill, AutoScroll = true };
    private readonly Panel _detailsPanel = new() { Dock = DockStyle.Fill, AutoScroll = true, Visible = false };
    private readonly InfoTable _details = new() { Location = new Point(0, 12), KeyWidth = 130 };
    private readonly Panel _logPanel = new() { Dock = DockStyle.Fill, Visible = false };
    private readonly FlowLayoutPanel _logBar = new() { Dock = DockStyle.Top, AutoSize = true, WrapContents = true };
    private readonly LinkLabel _logCopy = new() { Text = T("Copy"), AutoSize = true, Margin = new Padding(0, 7, 12, 0) };
    private readonly TextBox _log = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 9f), BorderStyle = BorderStyle.None };
    // the Log tab shows the lines about the selected device (all of them when nothing is selected or the box is unticked)
    private readonly CheckBox _logOnlySel = new() { Text = T("Only lines about the selected device"), Checked = true, AutoSize = true, FlatStyle = FlatStyle.Flat, Margin = new Padding(2, 5, 12, 0) };
    private readonly Label _logInfo = new() { AutoSize = true, Margin = new Padding(0, 7, 12, 0) };
    private readonly List<string> _logAll = new();
    private Regex? _logFilter;
    private Device? _logFor;
    private int _logShown;

    // status
    private readonly StatusStrip _status = new() { SizingGrip = true };
    private readonly ToolStripStatusLabel _stCount = new(T("0 devices")) { Tag = "muted" };
    private readonly ToolStripStatusLabel _stState = new("") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly ToolStripProgressBar _stProgress = new() { Style = ProgressBarStyle.Marquee, Visible = false, Width = 120 };
    private readonly ToolStripStatusLabel _stCompany = new("© " + AppInfo.Company) { Tag = "muted" };

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
    private int _panelWidth;
    private bool _cleared;
    private readonly bool _justUpdated;
    private readonly string? _whatsNew; // short list of changes, shown once after an update
    // NETFINDER_DEMO=1: made-up devices, nothing is scanned (screenshots). NETFINDER_SCREENSHOT=folder: save pictures and close.
    private readonly bool _demo = Environment.GetEnvironmentVariable("NETFINDER_DEMO") == "1";
    private readonly string? _shotDir = Environment.GetEnvironmentVariable("NETFINDER_SCREENSHOT");

    private int S(int px) => LogicalToDeviceUnits(px);
    /// <summary>Like S, and also bigger when Windows makes the text bigger than the scaling (so columns and panes still fit their text).</summary>
    private int F(int px) => (int)Math.Round(S(px) * Ui.TextFactor(this));

    public MainForm(bool justUpdated = false)
    {
        _justUpdated = justUpdated;
        var lastVersion = _settings.LastVersion;
        if (justUpdated || (lastVersion != null && UpdateChecker.IsNewer(AppInfo.Version, lastVersion)))
            _whatsNew = Changelog.Text(Changelog.Since(lastVersion));
        if (lastVersion != AppInfo.Version && !_demo) { _settings.LastVersion = AppInfo.Version; _settings.Save(); }
        if (_demo) _whatsNew = null;
        Theme.SetDark(_settings.DarkMode && _shotDir == null);
        Text = $"{AppInfo.Name} {AppInfo.Version}  –  {AppInfo.Company}";
        Font = Theme.Base;
        Icon = Theme.AppIcon();
        var work = Screen.PrimaryScreen?.WorkingArea.Size ?? new Size(1600, 900);
        ClientSize = new Size(Math.Min(S(1400), work.Width * 92 / 100), Math.Min(S(860), work.Height * 92 / 100));
        MinimumSize = new Size(S(1000), S(600));
        StartPosition = FormStartPosition.CenterScreen;

        _engine = new NetworkEngine(_settings, typeof(MainForm).Assembly);
        _watchList = _demo ? Core.Demo.DemoNetwork.Watched() : _settings.Watch;
        _watcher = new Watcher(_demo ? Core.Demo.DemoNetwork.WatchProbe : null, OpenPortsFor);
        _watcher.Changed += (s, before) => _watchEvents.Enqueue((s, before));
        _watcher.Checked += () => _watchChecked = true;
        Core.Export.PdfReport.ComplexText = PdfPicture;
        if (!string.IsNullOrWhiteSpace(_settings.UpdateSource)) UpdateChecker.Source = _settings.UpdateSource;
        _engine.Store.Labels = _demo ? new UserLabels() : UserLabels.Load();
        _reach = new ReachManager(_engine);

        _rangeWidth = _rangeBox.Width;
        _rangeHost = new ToolStripControlHost(_rangeBox) { AutoSize = false, Size = _rangeBox.Size, Margin = new Padding(0, 0, S(8), 0) };
        BuildToolbar();
        BuildBanners();
        BuildNav();
        BuildGrid();
        BuildDetailsPane();
        BuildStatus();

        // Dock order: the control added LAST is docked FIRST (top-most).
        _split.Panel1.Padding = new Padding(S(20), S(14), S(20), S(18));
        _split.Panel1.Controls.Add(_gridCard);
        _split.Panel1.Controls.Add(_titleRow);
        _split.Panel2.Padding = new Padding(S(18), S(16), S(18), S(8));
        _split.Panel2.Controls.Add(_tabBody);
        _split.Panel2.Controls.Add(new Panel { Dock = DockStyle.Top, Height = S(10) });
        _split.Panel2.Controls.Add(_tabs);
        _split.Panel2.Controls.Add(new Panel { Dock = DockStyle.Top, Height = S(12) });
        _split.Panel2.Controls.Add(_detailsHead);
        Controls.Add(_split);
        Controls.Add(_navHost);
        Controls.Add(_banner);
        Controls.Add(_updateBanner);
        Controls.Add(_tools);
        Controls.Add(_status);

        _engine.Store.Changed += d => _dirty[d.Key] = d;
        _engine.Store.Removed += d => _removed.Enqueue(d);
        _engine.Store.Cleared += () => _cleared = true;
        _engine.LogMessage += m => _logQueue.Enqueue(m);
        _uiTimer.Tick += (_, _) => FlushUi();
        _repeatTimer.Tick += async (_, _) => { if (_scanCts == null) await ScanAsync(); };
        _updateTimer.Tick += async (_, _) => await CheckForUpdatesAsync(manual: false);

        ApplyTheme();
        Load += (_, _) => Startup();
        HandleCreated += (_, _) => ApplyNativeTheme();
        Shown += (_, _) =>
        {
            LayoutSplit();
            ApplyNativeTheme();
            if (_shotDir != null) { BeginInvoke(new Action(async () => await TakeScreenshotsAsync(_shotDir))); return; }
            if (_whatsNew != null)
                BeginInvoke(() => Ui.Box(this,
                    T($"{AppInfo.Name} was updated to version {AppInfo.Version}.") + (_whatsNew.Length > 0 ? T("\n\nWhat's new:\n") + _whatsNew : ""),
                    AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information));
            else if (RunningFromZip())
                BeginInvoke(() => Ui.Box(this,
                    T($"{AppInfo.Name} is running from INSIDE the zip file (Windows put it in a temporary folder).\n\n" +
                    $"Updates cannot replace it there, so it will keep opening the old version.\n\n" +
                    $"Close it, right-click the zip → \"Extract All\", and run NetFinder.exe from the extracted folder (e.g. Desktop or C:\\Tools)."),
                    AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning));
        };
        FormClosing += OnClosing;
    }

    /// <summary>The details pane keeps its width; the list takes the rest.</summary>
    private void LayoutSplit()
    {
        try
        {
            _split.Panel1MinSize = S(360);
            _split.Panel2MinSize = Math.Min(F(340), _split.Width / 2);
            _split.SplitterDistance = Math.Max(S(360), _split.Width - Math.Min(F(412), _split.Width * 45 / 100));
        }
        catch (InvalidOperationException) { }
        catch (ArgumentOutOfRangeException) { }
    }

    // ───────────────────────────── layout ─────────────────────────────

    private void BuildToolbar()
    {
        _tools.Resize += (_, _) => FitHeader();
        _tools.Renderer = _renderer;
        _tools.Padding = new Padding(S(14), S(9), S(14), S(9));
        _btnScan.Click += async (_, _) => await ScanAsync(startOver: true);
        _btnStop.Click += (_, _) => _scanCts?.Cancel();
        _btnListen.CheckedChanged += (_, _) => ToggleListen(_btnListen.Checked);
        _chkRepeat.CheckedChanged += (_, _) => { if (_chkRepeat.Checked) _repeatTimer.Start(); else _repeatTimer.Stop(); ShowListenText(); };
        _settings.DeepScan = false; // starts off each time, like Repeat (it makes every scan ~45 s longer)
        _chkDeep.CheckedChanged += (_, _) => _settings.DeepScan = _chkDeep.Checked;
        _chkDark.Checked = Theme.P.Dark;
        _chkDark.CheckedChanged += (_, _) =>
        {
            Theme.SetDark(_chkDark.Checked);
            if (!_demo) { _settings.DarkMode = _chkDark.Checked; _settings.Save(); }
            ApplyTheme();
        };
        _txtRange.Text = _settings.ScanRanges;
        _txtRange.PlaceholderText = T("auto (my subnet)");
        _txtRange.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await ScanAsync(startOver: true); } };
        new ToolTip().SetToolTip(_txtRange, T("Empty = automatic (my subnet).\nOr type ranges: 10.10.20.1-254, 10.10.0.0/16, 192.168.5.*"));
        _txtFilter.TextChanged += (_, _) => ApplyFilter();
        _txtFilter.PlaceholderText = T("Filter: IP, name, model…");

        foreach (var b in new ToolStripItem[] { _btnScan, _btnStop, _btnModels, _btnListen })
        {
            b.Padding = new Padding(S(12), S(6), S(12), S(6));
            b.Margin = new Padding(S(4), 0, S(4), 0);
        }
        _btnListen.Margin = new Padding(S(10), 0, S(4), 0);
        foreach (var t in new[] { _chkRepeat, _chkDeep })
        {
            t.Padding = new Padding(S(9), S(6), S(12), S(6));
            t.Margin = new Padding(S(4), 0, S(4), 0);
            ChromeRenderer.SetToggleImage(t);
            t.CheckedChanged += (_, _) => ChromeRenderer.SetToggleImage(t);
            t.EnabledChanged += (_, _) => ChromeRenderer.SetToggleImage(t);
        }
        _tools.Items.AddRange(new ToolStripItem[]
        {
            _brand,
            _rangeLabel,
            _rangeHost,
            _btnScan, _btnStop, _chkRepeat, _chkDeep, _btnModels, _btnListen,
        });
        _btnModels.Click += async (_, _) => { if (_modelsCts != null) _modelsCts.Cancel(); else await GetModelsForAllAsync(); };

        var clear = new ToolStripMenuItem(T("Clear the list"));
        clear.Click += (_, _) => { _lastList = null; _engine.Store.Clear(); _engine.LearnedSubnets.Clear(); };
        var settings = new ToolStripMenuItem(T("Settings…"));
        settings.Click += (_, _) =>
        {
            bool changed;
            using (var f = new SettingsForm(_settings, _engine.Plugins)) changed = f.ShowDialog(this) == DialogResult.OK && f.LanguageChanged;
            if (changed) AskRestartForLanguage();
        };
        var about = new ToolStripMenuItem(T("About / check for updates…"));
        about.Click += async (_, _) => { if (Dialogs.About(this)) await CheckForUpdatesAsync(manual: true); };
        var watch = new ToolStripMenuItem(T("Watch devices…")) { ToolTipText = T("Ping chosen devices and tell me when one goes down or comes back") };
        watch.Click += (_, _) => PickWatched();
        _menu.DropDown.Renderer = _renderer;
        _menu.DropDownItems.AddRange(new ToolStripItem[] { watch, new ToolStripSeparator(), _chkDark, new ToolStripSeparator(), clear, settings, about });
        foreach (ToolStripItem i in _menu.DropDownItems) { i.Font = Theme.Header; i.Padding = new Padding(0, S(3), 0, S(3)); }
        _menu.Padding = new Padding(S(10), S(6), S(10), S(6));

        _export.Padding = new Padding(S(12), S(6), S(12), S(6));
        _export.DropDown.Renderer = _renderer;
        foreach (var (text, ext) in new[] { (T("Excel workbook (.xlsx)"), ".xlsx"), (T("PDF report (.pdf)"), ".pdf"), (T("CSV – opens in Excel (.csv)"), ".csv"), (T("Web page (.html)"), ".html") })
        {
            var item = new ToolStripMenuItem(text) { Font = Theme.Header, Padding = new Padding(0, S(3), 0, S(3)) };
            item.Click += (_, _) => Export(ext);
            _export.DropDownItems.Add(item);
        }
        _rangeLabel.Margin = new Padding(S(6), 0, S(6), 0);
        foreach (var b in new ToolStripItem[] { _menu, _export })
        {
            b.Alignment = ToolStripItemAlignment.Right;
            b.Margin = new Padding(S(4), 0, S(4), 0);
            _tools.Items.Add(b);
        }
        ShowListenText();
    }

    private bool _listenCompact;

    private void ShowListenText() => ShowListenText(_listenCompact, fit: true);

    private void ShowListenText(bool compact, bool fit = false)
    {
        _listenCompact = compact;
        _btnListen.Text = compact ? (_btnListen.Checked ? "●" : "○") : _btnListen.Checked ? T("●  Listening") : T("○  Not listening");
        if (fit) FitHeader();
    }

    private bool _fitting;

    /// <summary>
    /// When the header is too narrow, the Range box gets shorter, then the "Range" label, the app name, the word
    /// "scan" of Deep scan and the word Listening go (in that order), so no button ever disappears.
    /// </summary>
    private void FitHeader()
    {
        if (_rangeHost.Owner == null || _fitting) return;
        _fitting = true;
        try
        {
            var min = F(110);
            int Room() => _tools.DisplayRectangle.Width - S(6) - _rangeHost.Margin.Horizontal - _tools.Items.Cast<ToolStripItem>()
                .Where(i => i.Available && i != _rangeHost).Sum(i => i.GetPreferredSize(Size.Empty).Width + i.Margin.Horizontal);
            // start full, then give up the least useful text until the Range box fits at its smallest
            _rangeLabel.Visible = true; _brand.Compact = false; _chkDeep.Text = T("Deep scan"); ShowListenText(compact: false);
            var steps = new Action[] { () => _rangeLabel.Visible = false, () => _brand.Compact = true, () => _chkDeep.Text = T("Deep"), () => ShowListenText(compact: true) };
            foreach (var step in steps)
            {
                if (Room() >= min) break;
                step();
            }
            var range = Math.Clamp(Room(), min, _rangeWidth);
            if (_rangeHost.Width != range) _rangeHost.Width = range;
            _tools.PerformLayout();
            _tools.Invalidate();
        }
        finally { _fitting = false; }
    }

    private void BuildBanners()
    {
        var install = new Button { Text = T("Install Npcap"), Dock = DockStyle.Right, Width = 120, FlatStyle = FlatStyle.Flat, Font = Theme.Bold };
        install.FlatAppearance.BorderSize = 0;
        install.Click += async (_, _) => { await InstallNpcapAsync(t => install.Text = t, e => install.Enabled = e); ShowCaptureMode(); };
        var hide = new LinkLabel { Text = T("Hide"), Dock = DockStyle.Right, Width = 50, TextAlign = ContentAlignment.MiddleCenter };
        hide.LinkClicked += (_, _) => _banner.Visible = false;
        _banner.Controls.Add(_bannerText);
        _banner.Controls.Add(new Panel { Dock = DockStyle.Right, Width = 8 });
        _banner.Controls.Add(install);
        _banner.Controls.Add(hide);

        var updNow = new Button { Text = T("Update now"), Dock = DockStyle.Right, Width = 110, FlatStyle = FlatStyle.Flat, Font = Theme.Bold };
        updNow.FlatAppearance.BorderSize = 0;
        updNow.Click += async (_, _) => await InstallUpdateAsync(updNow);
        var skip = new LinkLabel { Text = T("Later"), Dock = DockStyle.Right, Width = 60, TextAlign = ContentAlignment.MiddleCenter };
        skip.LinkClicked += (_, _) => _updateBanner.Visible = false;
        _updateBanner.Controls.Add(_updateText);
        _updateBanner.Controls.Add(new Panel { Dock = DockStyle.Right, Width = 8 });
        _updateBanner.Controls.Add(updNow);
        _updateBanner.Controls.Add(skip);
        _bannerButtons.AddRange(new[] { install, updNow });
        _bannerLinks.AddRange(new[] { hide, skip });
    }

    private void BuildNav()
    {
        _navHost.Width = F(220);
        _navHost.Padding = new Padding(0, 0, 1, 0);
        _nav.Section(T("Devices"));
        _nav.Add("all", T("All devices"));
        _nav.Add("pc", T("Computers"));
        _nav.Add("server", T("Servers & VMs"));
        _nav.Add("camera", T("Cameras & NVR"));
        _nav.Add("printer", T("Printers"));
        _nav.Add("network", T("Network"));
        _nav.Add("storage", T("Storage (NAS)"));
        _nav.Add("phone", T("Phones & TV"));
        _nav.Add("other", T("Other"));
        _nav.Section(T("Networks"));
        _nav.Add("net:mine", T("My subnet")).Sub = "";
        _nav.Add("net:routed", T("Behind a router")).Hidden = true;
        _nav.Add("net:other", T("Other subnets")).Sub = T("found by listening");
        _nav.Section(T("Checks"));
        _nav.Add("watch", T("Watched")).Sub = T("pick devices…");
        _nav.Add("risky", T("Risky ports"));
        _nav.SelectedChanged += key =>
        {
            _title.Text = key switch { "all" => T("All devices"), "watch" => T("Watched devices"), "risky" => T("Devices with risky ports"), _ => _nav.TextOf(key) };
            _watchPick.Visible = key == "watch";
            ApplyFilter();
            if (key == "watch" && _watchList.Count == 0) BeginInvoke(PickWatched);
        };

        var w = _navHost.Width - 1 - S(24);
        _navBottom.Padding = new Padding(S(12), S(8), S(12), S(14));
        _adapterLabel.Margin = new Padding(S(10), 0, 0, S(6));
        _cmbAdapter.Width = w;
        new ToolTip().SetToolTip(_cmbAdapter, T("Which network card to scan. All connected adapters = every real one (not the virtual ones of Hyper-V / VMware)."));
        _cmbAdapter.Margin = new Padding(0, 0, 0, S(12));
        _npcapCard.Width = w;
        _npcapCard.Margin = new Padding(0);
        _npcapCard.Click += async (_, _) => { if (!_demo) await NpcapButtonAsync(); };
        _navBottom.Controls.AddRange(new Control[] { _adapterLabel, _cmbAdapter, _npcapCard });
        _navTop.Padding = new Padding(S(12), S(12), S(12), S(4));
        _filterBox.Width = w;
        _filterBox.Dock = DockStyle.Fill;
        _navTop.Height = _filterBox.Height + _navTop.Padding.Vertical;
        _navTop.Controls.Add(_filterBox);
        _navHost.Controls.Add(_nav);
        _navHost.Controls.Add(_navBottom);
        _navHost.Controls.Add(_navTop);
    }

    private void BuildGrid()
    {
        _gridCard.Controls.Add(_grid);
        _titleRow.Padding = new Padding(0, 0, 0, S(12));
        _summary.Margin = new Padding(S(10), S(8), 0, 0);
        _titleRow.Controls.Add(_title);
        _titleRow.Controls.Add(_summary);
        _watchPick.Margin = new Padding(S(14), S(2), 0, 0);
        _watchPick.Click += (_, _) => PickWatched();
        _titleRow.Controls.Add(_watchPick);

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
        _grid.ColumnHeadersDefaultCellStyle.Font = Theme.Bold;
        _grid.ColumnHeadersDefaultCellStyle.Padding = new Padding(S(6), S(9), S(6), S(9));
        _grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
        _grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
        _grid.DefaultCellStyle.Padding = new Padding(S(6), 0, S(6), 0);
        _grid.RowTemplate.Height = F(38);
        _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None;
        typeof(DataGridView).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)?.SetValue(_grid, true);

        DataGridViewColumn Col(string name, string header, int width)
        {
            var c = new DataGridViewTextBoxColumn { Name = name, HeaderText = header, Width = F(width), SortMode = DataGridViewColumnSortMode.Automatic, MinimumWidth = S(50) };
            _grid.Columns.Add(c);
            return c;
        }
        Col("Type", T("Type"), 160);
        var watchCol = Col("Watch", T("Watch"), 122);
        watchCol.Visible = false;
        watchCol.ToolTipText = T("Ping result of the watched devices (☰ menu → Watch devices…)");
        Col("Ip", T("IP address"), 124).DefaultCellStyle.Font = Theme.Mono;
        Col("Name", T("Name"), 140);
        Col("Model", T("Model"), 180).DefaultCellStyle.Font = Theme.Bold;
        // shown once a printer told its toner levels / a switch told its ports (SNMP)
        var inkCol = Col("Ink", T("Ink / toner"), 200);
        inkCol.Visible = false;
        inkCol.ToolTipText = T("Toner or ink left in each printer (read over SNMP)");
        var portCol = Col("SwPort", T("Switch port"), 170);
        portCol.Visible = false;
        portCol.ToolTipText = T("The switch and port each device is plugged into (read from the switches over SNMP)");
        Col("Vendor", T("Vendor"), 105);
        _grid.Columns.Add(new DataGridViewLinkColumn
        {
            Name = "Open", HeaderText = T("Open"), Width = F(100), SortMode = DataGridViewColumnSortMode.Automatic, TrackVisitedState = false,
            LinkBehavior = LinkBehavior.HoverUnderline, ToolTipText = T("Click to open the device (web page, Remote Desktop, SSH… whatever it has open)"),
        });
        Col("Mac", T("MAC"), 135).DefaultCellStyle.Font = Theme.Mono;
        Col("Net", T("Network"), 150);
        Col("Ports", T("Open ports"), 130);
        Col("Via", T("Found via"), 140);
        Col("Seen", T("Last seen"), 80);

        _grid.SortCompare += (_, e) =>
        {
            if (e.Column.Name == "Ip")
            {
                e.SortResult = IpKey(e.CellValue1).CompareTo(IpKey(e.CellValue2));
                e.Handled = true;
            }
        };
        _grid.CellPainting += PaintCell;
        _grid.RowPostPaint += (_, e) =>
        {
            if (e.RowIndex < 0 || !_grid.Rows[e.RowIndex].Selected) return;
            using var b = new SolidBrush(Theme.P.Accent);
            e.Graphics.FillRectangle(b, e.RowBounds.Left, e.RowBounds.Top, S(3), e.RowBounds.Height - 1);
        };
        _grid.SelectionChanged += (_, _) => SelectDevice(SelectedDevice());
        _grid.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0 && _grid.Columns[e.ColumnIndex].Name != "Open") OpenPrimary(SelectedDevice()); };
        _grid.CellContentClick += (_, e) =>
        {
            if (e.RowIndex >= 0 && e.ColumnIndex >= 0 && _grid.Columns[e.ColumnIndex].Name == "Open" && _grid.Rows[e.RowIndex].Tag is Device d) OpenPrimary(d);
        };
        _grid.ContextMenuStrip = BuildContextMenu();
        _grid.CellMouseDown += (_, e) =>
        {
            if (e.Button != MouseButtons.Right || e.RowIndex < 0) return;
            var row = _grid.Rows[e.RowIndex];
            _grid.ClearSelection();
            row.Selected = true;
            SetCurrent(row, e.ColumnIndex);
        };
    }

    private static long IpKey(object? v) =>
        v is string s && IPAddress.TryParse(s.Split(' ')[0], out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? Ip4.ToUInt(ip) : long.MaxValue;

    /// <summary>Header line, the type tile, and the "Firewall blocks it" chip in the Model column.</summary>
    private void PaintCell(object? sender, DataGridViewCellPaintingEventArgs e)
    {
        var g = e.Graphics;
        if (g == null || e.ColumnIndex < 0) return;
        var P = Theme.P;
        if (e.RowIndex < 0)
        {
            e.Paint(e.CellBounds, DataGridViewPaintParts.All);
            using var pen = new Pen(P.Border);
            g.DrawLine(pen, e.CellBounds.Left, e.CellBounds.Bottom - 1, e.CellBounds.Right, e.CellBounds.Bottom - 1);
            e.Handled = true;
            return;
        }
        var selected = (e.State & DataGridViewElementStates.Selected) != 0;
        var back = selected ? P.RowSelected : e.CellStyle?.BackColor ?? P.Surface;
        var name = _grid.Columns[e.ColumnIndex].Name;
        if (name == "Type")
        {
            e.PaintBackground(e.CellBounds, selected);
            var type = e.FormattedValue?.ToString() ?? "";
            var size = Math.Clamp(e.CellBounds.Height - S(12), 14, S(28));
            var r = new Rectangle(e.CellBounds.X + S(10), e.CellBounds.Y + (e.CellBounds.Height - size) / 2, size, size);
            Theme.DrawTypeTile(g, r, type, back);
            var textRect = new Rectangle(r.Right + S(10), e.CellBounds.Y, Math.Max(0, e.CellBounds.Right - r.Right - S(14)), e.CellBounds.Height);
            TextRenderer.DrawText(g, T(type), Theme.Base, textRect, type == DeviceTypes.Unknown ? P.Muted : P.Text, Ui.Line | (Rtl ? TextFormatFlags.Right | TextFormatFlags.RightToLeft : 0));
            e.Handled = true;
        }
        else if (name == "Ink" && _grid.Rows[e.RowIndex].Tag is Device { Printer: { Supplies.Count: > 0 } pst })
        {
            e.PaintBackground(e.CellBounds, selected);
            Ink.PaintCell(g, e.CellBounds, pst, S);
            e.Handled = true;
        }
        else if (name == "Watch" && e.FormattedValue?.ToString() is { Length: > 0 } watch)
        {
            e.PaintBackground(e.CellBounds, selected);
            var health = _grid.Rows[e.RowIndex].Tag is Device wd ? WatchHealth(wd) : Health.Unknown;
            var down = health == Health.Down;
            var up = health == Health.Up;
            var text = "●  " + watch;
            var tw = TextRenderer.MeasureText(g, text, Theme.Bold, Size.Empty, TextFormatFlags.NoPadding).Width;
            var chip = new Rectangle(e.CellBounds.X + S(6), e.CellBounds.Y + (e.CellBounds.Height - S(24)) / 2, Math.Min(tw + S(20), e.CellBounds.Width - S(10)), S(24));
            Ui.FillRound(g, chip, S(12), down ? P.BadSoft : up ? P.GoodSoft : P.Hover);
            TextRenderer.DrawText(g, text, Theme.Bold, chip, down ? P.Bad : up ? P.Good : P.Muted, Ui.Line | TextFormatFlags.HorizontalCenter);
            e.Handled = true;
        }
        else if (name == "Model" && string.IsNullOrEmpty(e.FormattedValue?.ToString()) && _grid.Rows[e.RowIndex].Tag is Device d)
        {
            string? status;
            lock (d) status = d.Info.GetValueOrDefault("Windows status");
            if (status == null) return;
            e.PaintBackground(e.CellBounds, selected);
            var text = "⚠  " + T(status);
            var tw = TextRenderer.MeasureText(g, text, Theme.Bold, Size.Empty, TextFormatFlags.NoPadding).Width;
            var chip = new Rectangle(e.CellBounds.X + S(6), e.CellBounds.Y + (e.CellBounds.Height - S(24)) / 2, Math.Min(tw + S(20), e.CellBounds.Width - S(10)), S(24));
            Ui.FillRound(g, chip, S(12), P.WarnSoft);
            TextRenderer.DrawText(g, text, Theme.Bold, chip, P.Warn, Ui.Line | TextFormatFlags.HorizontalCenter);
            e.Handled = true;
        }
    }

    private ContextMenuStrip BuildContextMenu()
    {
        var m = new ContextMenuStrip { Renderer = _renderer };
        var icons = Theme.P.Surface;
        var open = new ToolStripMenuItem(T("Open")) { Font = Theme.Bold, ToolTipText = T("Web page, Remote Desktop, SSH… whatever the device has open") };
        open.Click += (_, _) => OpenPrimary(SelectedDevice());
        m.Items.Add(open);
        m.Items.Add(T("Open in browser (http)"), null, (_, _) => OpenWeb(SelectedDevice(), "http"));
        m.Items.Add(T("Open in browser (https)"), null, (_, _) => OpenWeb(SelectedDevice(), "https"));
        m.Items.Add("SSH", null, async (_, _) => { if (SelectedDevice() is { Ip: { } ip } d) await RunAction(d, new DeviceAction("Remote", "SSH", () => Launcher.Ssh(ip.ToString()))); });
        m.Items.Add(T("Telnet"), null, async (_, _) => { if (SelectedDevice() is { Ip: { } ip } d) await RunAction(d, new DeviceAction("Remote", T("Telnet"), () => Launcher.Telnet(ip.ToString()))); });
        m.Items.Add(new ToolStripSeparator());
        m.Items.Add(T("Show cameras (NVR / DVR)…"), Theme.TypeIcon(DeviceTypes.Nvr, 16, icons), (_, _) => ShowCameras(SelectedDevice()));
        m.Items.Add(T("Make reachable (add temporary IP)"), null, async (_, _) => { if (SelectedDevice() is { } d) await MakeReachableAsync(d); });
        m.Items.Add(T("Check open ports"), null, async (_, _) => { if (SelectedDevice() is { } d) await CheckPortsAsync(d, force: true); });
        var watchThis = new ToolStripMenuItem(T("Watch this device")) { ToolTipText = T("Ping it and tell me when it goes down or comes back") };
        watchThis.Click += (_, _) => { if (SelectedDevice() is { } d) ToggleWatch(d); };
        m.Items.Add(watchThis);
        m.Items.Add(T("Watch devices…"), null, (_, _) => PickWatched());
        m.Opening += (_, _) =>
        {
            var d = SelectedDevice();
            string? ip = null;
            if (d != null) lock (d) ip = d.IsSelf ? null : d.Ip?.ToString();
            watchThis.Enabled = ip != null;
            watchThis.Checked = _watcher.Get(ip) != null;
        };
        m.Items.Add(T("Get model"), null, async (_, _) => { if (SelectedDevice() is { } d) await GetModelAsync(d); });
        m.Items.Add(T("Read ink levels / switch ports (SNMP)"), null, async (_, _) => { if (SelectedDevice() is { } d) await ReadSnmpAsync(d); });
        m.Items.Add(T("Get model with Windows login…"), null, async (_, _) => { if (SelectedDevice() is { } d) await GetWindowsModelAsync(d, askLogin: true); });
        m.Items.Add(new ToolStripSeparator());
        m.Items.Add(T("Copy IP"), null, (_, _) => { if (SelectedDevice()?.Ip is { } ip) Clipboard.SetText(ip.ToString()); });
        m.Items.Add(T("Copy MAC"), null, (_, _) => { if (SelectedDevice() is { Mac.Length: > 0 } d) Clipboard.SetText(d.Mac); });
        m.Items.Add(new ToolStripSeparator());
        m.Items.Add(T("Rename…"), null, (_, _) => Rename(SelectedDevice()));
        var setType = new ToolStripMenuItem(T("Set type"));
        setType.DropDown.Renderer = _renderer;
        setType.DropDownItems.Add(T("Automatic (detect)"), null, (_, _) => SetType(SelectedDevice(), null));
        setType.DropDownItems.Add(new ToolStripSeparator());
        foreach (var t in DeviceTypes.All.Where(t => t != DeviceTypes.Unknown))
            setType.DropDownItems.Add(T(t), Theme.TypeIcon(t, 16, icons), (_, _) => SetType(SelectedDevice(), t));
        m.Items.Add(setType);
        m.Items.Add(new ToolStripSeparator());
        m.Items.Add(T("Remove from list"), null, (_, _) => { if (SelectedDevice() is { } d) _engine.Store.Remove(d); });
        return m;
    }

    private void BuildDetailsPane()
    {
        _tabBody.Controls.Add(_devicePanel);
        _tabBody.Controls.Add(_detailsPanel);
        _tabBody.Controls.Add(_logPanel);
        _detailsPanel.Controls.Add(_details);
        _detailsPanel.Resize += (_, _) => FitDetails();
        _devicePanel.Resize += (_, _) =>
        {
            // re-render the overview at the new width (wrapping), at the next UI tick
            if (Math.Abs(_devicePanel.ClientSize.Width - _panelWidth) > S(6)) { _selectedRev = -1; _panelSig = ""; }
        };

        _logCopy.LinkClicked += (_, _) => { if (_log.TextLength > 0) Clipboard.SetText(_log.Text); };
        _logOnlySel.CheckedChanged += (_, _) => UpdateLogView(force: true);
        _logBar.Padding = new Padding(0, 0, 0, S(6));
        _logBar.Controls.AddRange(new Control[] { _logOnlySel, _logCopy, _logInfo });
        _logPanel.Controls.Add(_log);
        _logPanel.Controls.Add(_logBar);
        _log.BringToFront();

        _tabs.SelectedIndexChanged += i =>
        {
            _devicePanel.Visible = i == 0;
            _detailsPanel.Visible = i == 1;
            _logPanel.Visible = i == 2;
            if (i == 1) FitDetails();
            if (i == 2) { _log.SelectionStart = _log.TextLength; _log.ScrollToCaret(); }
        };
        UpdateLogView();
        ShowEmptyDevicePanel();
    }

    private void BuildStatus()
    {
        _status.Renderer = _renderer;
        _status.Padding = new Padding(S(14), S(3), S(4), S(3));
        _stExport.Click += (_, _) => _export.ShowDropDown();
        _status.Items.AddRange(new ToolStripItem[] { _stCount, new ToolStripSeparator(), _stState, _stProgress, _stExport, _stCompany });
    }

    // ───────────────────────────── theme ─────────────────────────────

    /// <summary>Colors every part of the window from Theme.P (light or dark).</summary>
    private void ApplyTheme()
    {
        var p = Theme.P;
        SuspendLayout();
        BackColor = p.Bg;
        ForeColor = p.Text;
        _tools.BackColor = p.Surface;
        _status.BackColor = p.Surface;
        _rangeBox.ApplyTheme();
        _filterBox.ApplyTheme();
        _banner.BackColor = p.WarnSoft;
        _bannerText.ForeColor = p.Text;
        _updateBanner.BackColor = p.AccentSoft;
        _updateText.ForeColor = p.AccentSoftText;
        foreach (var b in _bannerButtons) { b.BackColor = p.Accent; b.ForeColor = p.AccentText; }
        foreach (var l in _bannerLinks) { l.LinkColor = p.Link; l.ActiveLinkColor = p.Link; }

        _navHost.BackColor = p.Border;
        _navBottom.BackColor = p.Surface2;
        _navTop.BackColor = p.Surface2;
        foreach (var t in new[] { _chkRepeat, _chkDeep }) ChromeRenderer.SetToggleImage(t);
        _adapterLabel.ForeColor = p.Muted;
        _cmbAdapter.Invalidate();

        _split.BackColor = p.Border;
        _split.Panel1.BackColor = p.Bg;
        _split.Panel2.BackColor = p.Surface;
        _titleRow.BackColor = p.Bg;
        _title.ForeColor = p.Text;
        _summary.ForeColor = p.Muted;
        _gridCard.BackColor = p.Border;

        _grid.BackgroundColor = p.Surface;
        _grid.GridColor = p.Border;
        _grid.DefaultCellStyle.BackColor = p.Surface;
        _grid.DefaultCellStyle.ForeColor = p.Text;
        _grid.DefaultCellStyle.SelectionBackColor = p.RowSelected;
        _grid.DefaultCellStyle.SelectionForeColor = p.Text;
        _grid.ColumnHeadersDefaultCellStyle.BackColor = p.Surface;
        _grid.ColumnHeadersDefaultCellStyle.ForeColor = p.Muted;
        _grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = p.Surface;
        _grid.ColumnHeadersDefaultCellStyle.SelectionForeColor = p.Muted;
        if (_grid.Columns["Open"] is DataGridViewLinkColumn open) { open.LinkColor = p.Link; open.ActiveLinkColor = p.Link; open.VisitedLinkColor = p.Link; }
        foreach (var name in new[] { "Vendor", "Mac", "Via", "Seen", "Ports" }) _grid.Columns[name].DefaultCellStyle.ForeColor = p.Muted;
        var oldMenu = _grid.ContextMenuStrip;
        _grid.ContextMenuStrip = BuildContextMenu();
        oldMenu?.Dispose();
        foreach (var row in _rows.Values) if (row.Tag is Device d) FillRow(row, d);

        foreach (var c in new Control[] { _tabBody, _devicePanel, _detailsPanel, _logPanel, _logBar }) c.BackColor = p.Surface;
        _log.BackColor = p.Surface;
        _log.ForeColor = p.Text;
        _logOnlySel.ForeColor = p.Text;
        _logOnlySel.BackColor = p.Surface;
        _logInfo.ForeColor = p.Muted;
        _logCopy.LinkColor = p.Link;
        _logCopy.ActiveLinkColor = p.Link;
        _stExport.LinkColor = p.Link;
        _stExport.ActiveLinkColor = p.Link;
        ResumeLayout();

        _selectedRev = -1; _panelSig = "";
        if (_selected == null) ShowEmptyDevicePanel(); else RefreshSelected();
        ApplyNativeTheme();
        Invalidate(true);
    }

    /// <summary>Title bar and scroll bars follow the theme (Windows 10 2004+ / 11).</summary>
    private void ApplyNativeTheme()
    {
        if (!IsHandleCreated) return;
        var dark = Theme.P.Dark;
        Native.DarkTitleBar(this, dark);
        foreach (var c in new Control[] { _grid, _log, _devicePanel, _detailsPanel }) Native.DarkScrollbars(c, dark);
    }

    // ───────────────────────────── screenshots ─────────────────────────────

    /// <summary>NETFINDER_SCREENSHOT=folder: light.png and dark.png of the demo list at 1440×900, then close.</summary>
    private async Task TakeScreenshotsAsync(string dir)
    {
        try
        {
            Directory.CreateDirectory(dir);
            var border = Size - ClientSize;
            MaximumSize = new Size(5000, 4000);
            Native.ForceSize(this, 1440 + border.Width, 900 + border.Height);
            await Task.Delay(800);
            LayoutSplit();
            await Task.Delay(1500);
            var pc = _rows.Values.FirstOrDefault(r => r.Tag is Device d && d.Ip?.ToString() == "10.0.0.45") ?? _rows.Values.FirstOrDefault();
            if (pc != null) { _grid.ClearSelection(); pc.Selected = true; _grid.CurrentCell = pc.Cells["Ip"]; }
            await Task.Delay(1500);
            Shot(Path.Combine(dir, "light.png"));
            var header = new List<string> { HeaderCheck() };
            _tabs.SelectedIndex = 1;
            await Task.Delay(700);
            Shot(Path.Combine(dir, "light-all-details.png"));
            _tabs.SelectedIndex = 0;
            await ShotModelsDialogAsync(Path.Combine(dir, "light-get-models-dialog.png"));
            // 1.1.15: risky ports, watched devices, the watch dialog, a PDF report
            SelectIp("10.0.0.2");
            await Task.Delay(900);
            _devicePanel.AutoScrollPosition = new Point(0, _devicePanel.DisplayRectangle.Height);
            await Task.Delay(500);
            Shot(Path.Combine(dir, "light-risky-ports.png"));
            _nav.Select("watch");
            SelectIp("10.0.0.201");
            await Task.Delay(1200);
            Shot(Path.Combine(dir, "light-watched.png"));
            await ShotWatchDialogAsync(Path.Combine(dir, "light-watch-dialog.png"));
            // 1.1.18: Windows servers (a domain controller found only by its ports, and two Windows Server VMs)
            _nav.Select("server");
            SelectIp("10.0.0.10");
            await Task.Delay(1200);
            Shot(Path.Combine(dir, "light-servers.png"));
            // 1.1.21: printers' toner / ink and switch ports (SNMP)
            var snmp = await SnmpShotsAsync(dir);
            _nav.Select("all");
            Core.Export.Exporter.Save(Path.Combine(dir, "report.pdf"), _rows.Values.Select(r => r.Tag).OfType<Device>().ToList(), ExportTitle(), WatchExportText);
            SelectIp("10.0.0.45");
            await Task.Delay(500);
            _chkDark.Checked = true; // switches to dark (not saved in demo mode)
            await Task.Delay(1500);
            Shot(Path.Combine(dir, "dark.png"));
            _nav.Select("network");
            SelectIp("10.0.0.2");
            await Task.Delay(1200);
            Shot(Path.Combine(dir, "dark-switch.png"));
            _nav.Select("printer");
            SelectIp("10.0.0.201");
            _grid.FirstDisplayedScrollingColumnIndex = _grid.Columns["Name"]!.Index;
            await Task.Delay(1200);
            Shot(Path.Combine(dir, "dark-printers.png"));
            _nav.Select("all");
            SelectIp("10.0.0.45");
            _nav.Select("pc");
            _tabs.SelectedIndex = 2;
            await Task.Delay(1000);
            Shot(Path.Combine(dir, "dark-computers-log.png"));
            _chkRepeat.Checked = true;
            _chkDeep.Checked = true;
            Native.ForceSize(this, 1100 + border.Width, 720 + border.Height);
            await Task.Delay(1200);
            Shot(Path.Combine(dir, "dark-narrow.png"));
            header.Add(HeaderCheck() + $" (Repeat {_chkRepeat.Checked}, Deep scan {_chkDeep.Checked}, timer on {_repeatTimer.Enabled})");
            _chkRepeat.Checked = false;
            _chkDeep.Checked = false;
            // 1.1.17: right-clicks on rows, with the Watch column shown and hidden (it used to fail when hidden)
            var rc = await RightClickCheckAsync(dir);
            rc.Add(await ArpTableCheckAsync());
            rc.Add(await BrowserCheckAsync());
            // a new scan in demo mode: the list empties, the devices come back with what was read from them
            if (_engine.Store.Find("10.0.0.43") is { } t43) _engine.Store.Touch(t43, x => x.Info["Serial number"] = "RESTORE-TEST");
            var before = _engine.Store.Count;
            StartOver();
            var rightAfter = _rows.Count;
            Core.Demo.DemoNetwork.Fill(_engine); // all at once, like Npcap finding a whole subnet in a second
            await Task.Delay(250);
            var atPause = _rows.Count;
            await Task.Delay(600);
            var filling = _rows.Count;
            Shot(Path.Combine(dir, "dark-new-scan-filling.png"));
            await Task.Delay(2400);
            var reveal = $"reveal: {rightAfter} rows right after Scan, {atPause} at 0.25 s, {filling} at 0.85 s, {_rows.Count} at 3.25 s, still revealing: {_revealing}, timer {_uiTimer.Interval} ms";
            var serial = _engine.Store.Find("10.0.0.43") is { } back ? back.Info.GetValueOrDefault("Serial number") : null;
            File.WriteAllText(Path.Combine(dir, "info.txt"), $"client {ClientSize.Width}x{ClientSize.Height}, dpi {DeviceDpi}, screen {Screen.PrimaryScreen?.Bounds.Size}\r\n" +
                $"new scan: {before} before, {_engine.Store.Count} in store after, {_rows.Count} rows, serial kept: {serial}, kept aside: {_engine.Store.KeptAside}, did not answer: {Gone().Count}\r\n{reveal}\r\n{string.Join("\r\n", header)}\r\n{snmp}\r\n" +
                string.Join("\r\n", rc));
        }
        catch (Exception ex) { try { File.WriteAllText(Path.Combine(dir, "error.txt"), ex.ToString()); } catch { } }
        Close();
    }

    /// <summary>
    /// Makes a cell of this row the current one: the clicked column when it is shown, else the IP address.
    /// Never a hidden cell (the hidden Watch column made every right-click fail in 1.1.15 and 1.1.16).
    /// </summary>
    private void SetCurrent(DataGridViewRow row, int column = -1)
    {
        if (!row.Visible || row.DataGridView != _grid) return;
        var col = column >= 0 && column < _grid.Columns.Count && _grid.Columns[column].Visible ? _grid.Columns[column] : _grid.Columns["Ip"];
        if (col is { Visible: true } && _grid.CurrentCell != row.Cells[col.Index]) _grid.CurrentCell = row.Cells[col.Index];
    }

    /// <summary>Screenshot self-check: every header item fits (a ToolStrip without overflow hides what does not fit).</summary>
    private string HeaderCheck()
    {
        var hidden = _tools.Items.Cast<ToolStripItem>().Where(i => i.Available && i.Placement != ToolStripItemPlacement.Main)
            .Select(i => string.IsNullOrEmpty(i.Text) ? i.GetType().Name : i.Text).ToList();
        return $"header at {ClientSize.Width}px: {(hidden.Count == 0 ? "all items shown" : "HIDDEN: " + string.Join(", ", hidden))}, range box {_rangeHost.Width}px, " +
               $"compact: {(_rangeLabel.Visible ? "" : "no Range label, ")}{(_brand.Compact ? "logo only, " : "")}Deep \"{_chkDeep.Text}\", Listening \"{_btnListen.Text}\"; filter box {_filterBox.Width}px in the side menu";
    }

    /// <summary>
    /// Screenshot self-check: does a web link really load in a browser? (1.1.20: Chrome opened an empty window.)
    /// A tiny web server on this PC counts which link the browser asked for: the new way (through Explorer) first, then the old one.
    /// </summary>
    private static async Task<string> BrowserCheckAsync()
    {
        var hits = new ConcurrentQueue<string>();
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource();
        var serve = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    using var c = await listener.AcceptTcpClientAsync(cts.Token);
                    var st = c.GetStream();
                    var buf = new byte[8192];
                    var n = await st.ReadAsync(buf, cts.Token);
                    var head = Encoding.ASCII.GetString(buf, 0, n);
                    var ua = Regex.Match(head, @"User-Agent: ([^\r\n]+)").Groups[1].Value;
                    hits.Enqueue(head.Split("\r\n")[0] + " | " + (ua.Contains("Edg/") ? "Edge" : ua.Contains("Chrome/") ? "Chrome" : ua.Contains("Firefox") ? "Firefox" : ua));
                    const string body = "<html><body>NetFinder link check</body></html>";
                    await st.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}"), cts.Token);
                }
                catch { if (cts.IsCancellationRequested) return; }
            }
        });
        async Task<string> Try(string path, Func<string, bool> open)
        {
            try { if (!open($"http://127.0.0.1:{port}{path}")) return $"{path}: not tried (no desktop Explorer)"; }
            catch (Exception ex) { return $"{path}: could not start ({ex.Message})"; }
            for (var i = 0; i < 40 && !hits.Any(h => h.Contains(path)); i++) await Task.Delay(250);
            return $"{path}: " + (hits.FirstOrDefault(h => h.Contains(path)) is { } h ? "page loaded in " + h.Split(" | ")[1] : "NOT loaded within 10 s");
        }
        bool admin;
        using (var id = System.Security.Principal.WindowsIdentity.GetCurrent())
            admin = new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        var explorers = System.Diagnostics.Process.GetProcessesByName("explorer").Length;
        var a = await Try("/through-explorer", Launcher.OpenInUserBrowser);
        var b = await Try("/as-admin", u => { Launcher.OpenElevated(u); return true; });
        cts.Cancel();
        listener.Stop();
        try { await serve; } catch { }
        return $"web links (admin {admin}, explorer processes {explorers}): {a}; {b}";
    }

    /// <summary>Screenshot self-check on a real Windows: the ARP table read with GetIpNetTable2 must match "arp -a".</summary>
    private static async Task<string> ArpTableCheckAsync()
    {
        try
        {
            var gw = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                .SelectMany(n => n.GetIPProperties().GatewayAddresses).Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            if (gw != null) using (var p = new System.Net.NetworkInformation.Ping()) await p.SendPingAsync(gw, 1000);
            var withState = ArpCache.ReadWithState();
            var plain = ArpCache.Read();
            var a = withState.Where(e => e.Mac != DeviceStore.NoMac).Select(e => $"{e.Ip} {e.Mac}").ToHashSet();
            var b = plain.Select(e => $"{e.Ip} {e.Mac}").ToHashSet();
            var states = string.Join(", ", withState.GroupBy(e => e.State).Select(g => $"{g.Key} {g.Count()}"));
            var gwState = gw == null ? "none" : withState.Where(e => e.Ip.Equals(gw)).Select(e => $"{e.Mac} {e.State} fresh={e.Fresh}").FirstOrDefault() ?? "not in table";
            return $"arp table: {withState.Count} entries ({states}); arp -a: {plain.Count}; " +
                   $"in arp -a only: {b.Except(a).Count()} [{string.Join("; ", b.Except(a).Take(4))}]; read only: {a.Except(b).Count()} [{string.Join("; ", a.Except(b).Take(4))}]; gateway {gw}: {gwState}";
        }
        catch (Exception ex) { return "arp table check failed: " + ex.Message; }
    }

    /// <summary>Screenshot self-check: right-clicks rows the way Windows does and writes down what happened.</summary>
    private async Task<List<string>> RightClickCheckAsync(string dir)
    {
        var rc = new List<string>();
        _nav.Select("all");
        _tabs.SelectedIndex = 0;
        await Task.Delay(600);
        async Task ClickAsync(string ip, string column)
        {
            if (!_rows.TryGetValue(ip, out var row) || !row.Visible) { rc.Add($"right-click: {ip} not in the list"); return; }
            var col = _grid.Columns[column]!;
            if (!col.Visible) { rc.Add($"right-click: column {column} hidden"); return; }
            _grid.FirstDisplayedScrollingRowIndex = row.Index;
            await Task.Delay(200);
            var r = _grid.GetCellDisplayRectangle(col.Index, row.Index, true);
            if (r.Width == 0) { _grid.FirstDisplayedScrollingColumnIndex = col.Index; await Task.Delay(200); r = _grid.GetCellDisplayRectangle(col.Index, row.Index, true); }
            var p = new Point(r.Left + r.Width / 2, r.Top + r.Height / 2);
            Native.RightClick(_grid, p);
            await Task.Delay(500);
            var menu = _grid.ContextMenuStrip!;
            var opened = menu.Visible;
            if (!opened) { menu.Show(_grid, p); await Task.Delay(400); }
            rc.Add($"right-click on {column} of {ip}: selected {SelectedDevice()?.Ip}, current cell {_grid.CurrentCell?.OwningColumn?.Name}, menu {(opened ? "opened" : "shown by hand")}, {menu.Items.Count} items");
            menu.Close();
            await Task.Delay(300);
        }
        var watchCol = _grid.Columns["Watch"]!;
        rc.Add($"watch column shown: {watchCol.Visible}");
        await ClickAsync("10.0.0.43", "Name");
        await ClickAsync("10.0.0.12", "Watch");
        _watchList.Clear();
        ApplyWatchList(log: false);
        await Task.Delay(500);
        rc.Add($"nothing watched: watch column shown: {watchCol.Visible}, current cell now {_grid.CurrentCell?.OwningColumn?.Name}");
        if (_rows.TryGetValue("10.0.0.43", out var r43))
        {
            try { _grid.CurrentCell = r43.Cells[1]; rc.Add("old code (cell 1): no error"); }
            catch (InvalidOperationException ex) { rc.Add($"old code (cell 1): {ex.Message}"); }
        }
        await ClickAsync("10.0.0.45", "Type");
        await ClickAsync("10.0.0.2", "Ip");
        await ClickAsync("10.0.0.64", "Ports");
        rc.Add($"ui errors: {(File.Exists(Path.Combine(dir, "ui-errors.txt")) ? "YES, see ui-errors.txt" : "none")}");
        return rc;
    }

    private void SelectIp(string ip)
    {
        if (!_rows.TryGetValue(ip, out var row) || !row.Visible) return;
        _grid.ClearSelection();
        row.Selected = true;
        SetCurrent(row);
        _grid.FirstDisplayedScrollingColumnIndex = 0;
    }

    private async Task ShotWatchDialogAsync(string path)
    {
        var picks = _rows.Values.OrderBy(r => IpKey(r.Cells["Ip"].Value)).Select(r => r.Tag).OfType<Device>().Where(d => !d.IsSelf && d.Ip != null)
            .Select(d => new Dialogs.WatchPick(d.Ip!.ToString(), d.Mac, d.DisplayName == d.Model ? "" : d.DisplayName, d.EffectiveType, d.Model ?? "", Category(d), _watcher.Get(d.Ip.ToString()) != null))
            .ToList();
        using var d = Dialogs.WatchDialog(picks, _settings.WatchSeconds, true, out _);
        d.Form.StartPosition = FormStartPosition.Manual;
        d.Form.Location = new Point(Left + 220, Top + 60);
        d.Form.Show(this);
        await Task.Delay(900);
        Shot(path, d.Form);
        d.Form.Close();
        await Task.Delay(300);
    }

    /// <summary>Screenshots of the printers (toner bars), the switch (port squares), its ports window and the SNMP box; returns a self-check line.</summary>
    private async Task<string> SnmpShotsAsync(string dir)
    {
        var notes = new List<string>();
        _nav.Select("printer");
        SelectIp("10.0.0.201");
        _grid.FirstDisplayedScrollingColumnIndex = _grid.Columns["Name"]!.Index;
        await Task.Delay(1200);
        Shot(Path.Combine(dir, "light-printer.png"));
        var ink = _grid.Columns["Ink"]!;
        var port = _grid.Columns["SwPort"]!;
        notes.Add($"snmp: ink column shown {ink.Visible} ({ink.Width}px), switch port column shown {port.Visible}; " +
                  $"10.0.0.45 port: {(_rows.TryGetValue("10.0.0.45", out var r45) ? r45.Cells["SwPort"].Value : "?")}; 10.0.0.88 port: {(_rows.TryGetValue("10.0.0.88", out var r88) ? r88.Cells["SwPort"].Value : "?")}");
        var tables = _devicePanel.Controls.Cast<Control>().SelectMany(c => c.Controls.Cast<Control>()).OfType<InfoTable>().ToList();
        notes.Add($"printer panel: {tables.Sum(t => t.Rows.Count)} supply rows, panel width {_devicePanel.ClientSize.Width}px");
        _nav.Select("network");
        SelectIp("10.0.0.2");
        await Task.Delay(1200);
        Shot(Path.Combine(dir, "light-switch.png"));
        var grid = _devicePanel.Controls.Cast<Control>().SelectMany(c => c.Controls.Cast<Control>()).OfType<PortGrid>().FirstOrDefault();
        notes.Add(grid == null ? "switch panel: NO PORT SQUARES" : $"switch panel: {grid.Ports.Count} port squares in {grid.Width}x{grid.Height}px (panel {_devicePanel.ClientSize.Width}px)");
        _devicePanel.AutoScrollPosition = new Point(0, S(260));
        await Task.Delay(500);
        Shot(Path.Combine(dir, "light-switch-scrolled.png"));
        if (_engine.Store.Find("10.0.0.2") is { } sw)
        {
            using var f = new SwitchPortsForm(sw, _engine.Store.All, _ => { });
            f.StartPosition = FormStartPosition.Manual;
            f.Location = new Point(Left + 160, Top + 80);
            f.Show(this);
            await Task.Delay(900);
            Shot(Path.Combine(dir, "light-switch-ports.png"), f);
            notes.Add($"ports window {f.ClientSize.Width}x{f.ClientSize.Height}px");
            f.Close();
            await Task.Delay(300);
        }
        // a router that did not answer SNMP: the box for another community
        SelectIp("10.0.0.15");
        await Task.Delay(1000);
        Shot(Path.Combine(dir, "light-snmp-community.png"));
        _nav.Select("all");
        SelectIp("10.0.0.45");
        await Task.Delay(900);
        Shot(Path.Combine(dir, "light-plugged-into.png"));
        return string.Join("\r\n", notes);
    }

    /// <summary>The "Get models" dialog, shown without waiting for it, pictured, then closed.</summary>
    private async Task ShotModelsDialogAsync(string path)
    {
        using var d = Dialogs.ModelsDialog(71, 1, 31, null, out _);
        d.Form.StartPosition = FormStartPosition.Manual;
        d.Form.Location = new Point(Left + 260, Top + 140);
        d.Form.Show(this);
        await Task.Delay(900);
        Shot(path, d.Form);
        d.Form.Close();
        await Task.Delay(300);
    }

    private void Shot(string path) => Shot(path, this);

    private static void Shot(string path, Form f)
    {
        f.Refresh();
        using var full = Native.Capture(f) is { } b && !IsBlack(b) ? b : DrawnBitmap(f);
        var origin = f.PointToScreen(Point.Empty);
        var client = new Rectangle(origin.X - f.Left, origin.Y - f.Top, f.ClientSize.Width, f.ClientSize.Height);
        client.Intersect(new Rectangle(Point.Empty, full.Size));
        using var crop = full.Clone(client, full.PixelFormat);
        crop.Save(path, System.Drawing.Imaging.ImageFormat.Png);
    }

    private static Bitmap DrawnBitmap(Form f)
    {
        var b = new Bitmap(f.Width, f.Height);
        f.DrawToBitmap(b, new Rectangle(Point.Empty, f.Size));
        return b;
    }

    private static bool IsBlack(Bitmap b)
    {
        for (var i = 1; i < 10; i++)
            if (b.GetPixel(b.Width * i / 10, b.Height * i / 10).ToArgb() != Color.Black.ToArgb()) return false;
        return true;
    }

    // ───────────────────────────── startup ─────────────────────────────

    private void Startup()
    {
        _engine.LoadAdapters();
        if (_demo) { _engine.Adapters.Clear(); _engine.Adapters.Add(Core.Demo.DemoNetwork.Adapter()); }
        _cmbAdapter.Items.Clear();
        _cmbAdapter.Items.Add(T("All connected adapters"));
        foreach (var a in _engine.Adapters) _cmbAdapter.Items.Add(a);
        _cmbAdapter.SelectedIndex = 0;
        ShowMySubnets();
        _uiTimer.Start();
        ApplyWatchList(log: _watchList.Count > 0);
        if (_demo)
        {
            Core.Demo.DemoNetwork.Fill(_engine);
            _lastScan = DateTime.Today.AddHours(21).AddMinutes(11);
            ShowCaptureMode();
            _btnListen.Checked = true; // shows "Listening"; nothing is captured in demo mode
            _stState.Text = T("Scan finished. Still listening for new devices…");
            return;
        }

        ShowCaptureMode();
        var hasNpcap = Core.Net.WindowsNet.NpcapInstalled || _engine.CaptureDriver?.StartsWith("Npcap", StringComparison.OrdinalIgnoreCase) == true;
        _engine.Log($"Npcap installed: {hasNpcap}; capture: {(_engine.CaptureAvailable ? _engine.CaptureDriver : "none")}");
        if (!_engine.CaptureAvailable)
        {
            ShowNpcapBanner(T("Npcap is not installed. Devices on YOUR subnet are found with Windows ARP + ping, but devices on OTHER ranges (e.g. a camera still on 192.168.1.x) need Npcap. It is free; one click installs it."));
            _chkDeep.Enabled = false;
        }
        else if (!hasNpcap)
            ShowNpcapBanner(T($"Old capture driver found ({_engine.CaptureDriver}). It does not work well on Wi-Fi and misses devices. Install Npcap to replace it."));

        if (_justUpdated) _engine.Log($"Updated to version {AppInfo.Version}");
        _btnListen.Checked = true; // starts listening (Npcap, or raw socket without it)
        BeginInvoke(new Action(async () => await ScanAsync()));
        if (_settings.CheckForUpdates && UpdateChecker.Enabled)
        {
            _updateTimer.Start();
            BeginInvoke(new Action(async () => { await Task.Delay(5000); await CheckForUpdatesAsync(manual: false); }));
        }
    }

    /// <summary>The card at the bottom of the side menu: Full mode (Npcap) or Basic mode, click to install Npcap.</summary>
    private void ShowCaptureMode()
    {
        var hasNpcap = Core.Net.WindowsNet.NpcapInstalled || _engine.CaptureDriver?.StartsWith("Npcap", StringComparison.OrdinalIgnoreCase) == true;
        if (_demo) { _npcapCard.Tone = InfoCard.Kind.Good; _npcapCard.Title = T("Full mode · Npcap 1.80"); _npcapCard.Body = T("Sees devices on any subnet."); }
        else if (!_engine.CaptureAvailable)
        {
            _npcapCard.Tone = InfoCard.Kind.Warn;
            _npcapCard.Title = T("Basic mode (no Npcap)");
            _npcapCard.Body = T("Finds devices on your own subnet only. Click here to install Npcap (free) and see every subnet.");
        }
        else if (!hasNpcap)
        {
            _npcapCard.Tone = InfoCard.Kind.Warn;
            _npcapCard.Title = T($"Limited mode ({_engine.CaptureDriver})");
            _npcapCard.Body = T("Old capture driver: it misses devices, mostly on Wi-Fi. Click here to install Npcap.");
        }
        else
        {
            _npcapCard.Tone = InfoCard.Kind.Good;
            _npcapCard.Title = T($"Full mode · {_engine.CaptureDriver}");
            _npcapCard.Body = T("Sees devices on any subnet.");
        }
        new ToolTip().SetToolTip(_npcapCard, T("Npcap lets the program see devices on OTHER IP ranges. Click to install or reinstall it."));
    }

    /// <summary>"10.0.0.0/16 · Ethernet" under "My subnet" in the side menu.</summary>
    private void ShowMySubnets()
    {
        var nets = _engine.Adapters.Where(a => a.IsUp && !a.IsHostOnlyVirtual)
            .SelectMany(a => a.Addresses.Select(x => $"{x.Subnet} · {a.FriendlyName}")).Distinct().ToList();
        if (_nav.Find("net:mine") is { } mine) mine.Sub = nets.Count == 0 ? T("no IP address") : nets.Count == 1 ? nets[0] : $"{nets[0]} +{nets.Count - 1}";
        _nav.Invalidate();
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
            Ui.Box(this, T($"Npcap is installed ({_engine.CaptureDriver ?? T("driver not loaded")}).\n\nDownload and reinstall the latest Npcap anyway?"),
                AppInfo.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Information) != DialogResult.Yes) return;
        await InstallNpcapAsync(t => _npcapCard.Title = t, e => _npcapCard.Enabled = e);
        if (!IsDisposed) ShowCaptureMode();
    }

    private async Task InstallNpcapAsync(Action<string> setText, Action<bool> setEnabled)
    {
        setEnabled(false);
        try
        {
            // 1) an installer the user already downloaded?
            string? installer = NpcapInstaller.FindLocalInstaller();
            if (installer != null && Ui.Box(this,
                    T($"Found the Npcap installer {Path.GetFileName(installer)} in\n{Path.GetDirectoryName(installer)}\n\nInstall it?"),
                    AppInfo.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                installer = null;

            // 2) download it from npcap.com / nmap.org
            if (installer == null)
            {
                setText(T("Downloading…"));
                try { installer = await NpcapInstaller.DownloadAsync(new Progress<int>(p => setText(T($"Downloading {p}%"))), _lifetime.Token); }
                catch (NpcapInstaller.UnreachableException ex)
                {
                    _engine.Log("Npcap download failed: " + ex.Message.Replace('\n', ' '));
                    // 3) offline / site blocked: let the user pick a file copied from elsewhere
                    installer = AskForNpcapInstaller(ex.Message);
                    if (installer == null) return;
                }
            }

            setText(T("Installing…"));
            await NpcapInstaller.RunInstallerAsync(installer, _lifetime.Token);
            if (Core.Net.WindowsNet.NpcapInstalled)
            {
                Ui.Box(this, T($"Npcap is installed. {AppInfo.Name} will restart to use it."), AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                RestartApp();
                return;
            }
            Ui.Box(this, T("Npcap was not installed (the setup was closed or failed)."), AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _engine.Log("Npcap install failed: " + ex.Message);
            Ui.Box(this, T("Npcap could not be installed:\n\n") + ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally
        {
            if (!IsDisposed)
            {
                setText(Core.Net.WindowsNet.NpcapInstalled ? T("Npcap ✓") : T("Install Npcap"));
                setEnabled(true);
            }
        }
    }

    /// <summary>Shown when npcap.com can't be reached. Returns a chosen installer file, or null.</summary>
    private string? AskForNpcapInstaller(string technical)
    {
        var choose = new TaskDialogButton(T("Choose installer file…"));
        var open = new TaskDialogButton(T("Open npcap.com in browser"));
        var page = new TaskDialogPage
        {
            Caption = AppInfo.Name,
            Icon = TaskDialogIcon.Warning,
            Heading = T("This PC can't reach the Npcap website"),
            Text = T($"npcap.com and nmap.org could not be reached: there is no internet, or the site is blocked on this network.\n\n" +
                   $"Download the Npcap installer on another PC or phone from npcap.com (a file like npcap-1.80.exe), " +
                   $"copy it to this PC (e.g. with a USB stick), then press \"Choose installer file…\".\n\n" +
                   $"Tip: if you put it in your Downloads folder, {AppInfo.Name} finds it by itself next time."),
            Buttons = { choose, open, TaskDialogButton.Cancel },
            Expander = new TaskDialogExpander(technical) { CollapsedButtonText = T("Technical details") },
        };
        var result = TaskDialog.ShowDialog(this, page);
        if (result == open) { Core.Actions.Launcher.Open(NpcapInstaller.DownloadPage); return null; }
        if (result != choose) return null;
        using var dlg = new OpenFileDialog
        {
            Title = T("Choose the Npcap installer"),
            Filter = T("Npcap installer (npcap-*.exe)|npcap*.exe|Programs (*.exe)|*.exe"),
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
            if (manual) Ui.Box(this, T("No update source is set yet (Settings → Update source)."), AppInfo.Name);
            return;
        }
        try
        {
            var info = await UpdateChecker.CheckAsync(_lifetime.Token);
            if (info == null)
            {
                if (manual) Ui.Box(this, T($"You have the latest version ({AppInfo.Version})."), AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            _update = info;
            var summary = Changelog.OneLine(info.Notes);
            _updateText.Text = T($"New version {info.Version} is available (you have {AppInfo.Version})") +
                (summary.Length > 0 ? ":  " + summary : ".") +
                (RunningFromZip() ? T("  –  extract the zip first, updates can't work from inside it") : "");
            _updateBanner.Visible = true;
        }
        catch (Exception ex)
        {
            if (manual) Ui.Box(this, T("Could not check for updates: ") + ex.Message, AppInfo.Name);
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
            btn.Text = T("Update now");
            btn.Enabled = true;
            UpdateChecker.Log("FAILED: " + ex);
            Ui.Box(this, T("Update failed: ") + ex.Message + T("\n\nDetails: ") + UpdateChecker.LogPath + T("\n\nThe download page will open."), AppInfo.Name);
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
            if (!_demo)
            {
                if (on) _engine.StartListening(_engine.Adapters.Where(a => a.IsUp));
                else _engine.StopListening();
            }
            ShowListenText();
            _stState.Text = on ? T("Listening for devices…") : T("Not listening");
            UpdateSummary();
        }
        catch (Exception ex)
        {
            _btnListen.Checked = false;
            ShowListenText();
            _engine.Log("Listening failed: " + ex.Message);
        }
    }

    /// <param name="startOver">
    /// Scan button: the list starts empty and shows only the devices that answer now (what was learned about a device,
    /// like its model, comes back with it). The repeat timer adds to the list instead, so sleeping phones do not blink.
    /// </param>
    private async Task ScanAsync(bool startOver = false)
    {
        if (_scanCts != null) return;
        var rangeText = _txtRange.Text.Trim();
        if (!IpRange.TryParseList(rangeText, out _, out var err))
        {
            Ui.Box(this, err, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        if (rangeText != _settings.ScanRanges) { _settings.ScanRanges = rangeText; _settings.Save(); }
        _startedEmpty = startOver && _engine.Store.Count > 0;
        if (_startedEmpty) StartOver();

        _scanCts = new CancellationTokenSource();
        _btnScan.Enabled = false; _btnStop.Enabled = true; _btnStop.Visible = true; _stProgress.Visible = true;
        UpdateSummary();
        var progress = new Progress<string>(s => _stState.Text = s);
        try
        {
            await Task.Run(() => _engine.ScanAsync(SelectedAdapters(), _engine.Plugins.Scanners, progress, _scanCts.Token));
            if (startOver && _lastList != null)
            {
                var gone = Gone();
                _engine.Log($"New scan done: {_engine.Store.Count} device(s) answered" + (gone.Count == 0 ? T(", all of the last list too") :
                    T($"; {gone.Count} of the last list did not answer and are no longer listed: {string.Join(", ", gone.OrderBy(IpKey).Take(20))}{(gone.Count > 20 ? "…" : "")}")));
            }
            _stState.Text = T($"Scan finished at {DateTime.Now:HH:mm:ss}.") + (_engine.Listening ? T(" Still listening for new devices…") : "");
            _lastScan = DateTime.Now;
            _stExport.Visible = true;
        }
        catch (OperationCanceledException) { _stState.Text = T("Scan stopped."); }
        catch (Exception ex) { _stState.Text = T("Scan failed: ") + ex.Message; }
        finally
        {
            _scanCts.Dispose(); _scanCts = null;
            _btnScan.Enabled = true; _btnStop.Enabled = false; _btnStop.Visible = false; _stProgress.Visible = false;
            UpdateSummary();
        }
    }

    private string? _reselect;
    /// <summary>The devices listed before the last "Scan" emptied the list (to say how many did not answer again).</summary>
    private HashSet<string>? _lastList;
    private bool _startedEmpty;

    private List<string> Gone() => _lastList?.Where(k => _engine.Store.Find(k) == null && !k.StartsWith("MAC ")).ToList() ?? new List<string>();

    /// <summary>Empties the list for a new scan; the selected device is selected again when it answers.</summary>
    private void StartOver()
    {
        _reselect = _selected?.Key;
        _lastList = _engine.Store.All.Select(d => d.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var n = _engine.Store.Count;
        _engine.Store.StartOver();
        _engine.Log($"New scan: the list starts empty and shows the devices that answer now ({n} were listed before; what was read from them comes back when they answer)");
        // Empty the list on screen now (not at the next refresh, when the devices that answered at once would
        // already be back), then show the devices one after another so the new list is seen filling.
        _revealFrom = DateTime.Now;
        _revealing = true;
        FlushUi();
        UpdateCounters();
        _uiTimer.Interval = 90;
        _grid.Refresh();
    }

    // SNMP: printers' toner and switches' ports (1.1.21)
    private bool _showInk, _showPorts, _haveSwitches;
    private volatile bool _portMapRunning;
    private DateTime _portMapAt;
    private readonly HashSet<Device> _snmpBusy = new();

    /// <summary>After "Scan" emptied the list: new rows come in a few at a time, top to bottom, for about 2 s.</summary>
    private bool _revealing;
    private DateTime _revealFrom;
    private static readonly TimeSpan RevealPause = TimeSpan.FromMilliseconds(500);

    private void EndReveal()
    {
        _revealing = false;
        _uiTimer.Interval = 400;
    }

    // ───────────────────────────── UI refresh ─────────────────────────────

    private void FlushUi()
    {
        // which switch port each device is on: worked out again every few seconds while devices come and go
        if (_haveSwitches && !_portMapRunning && DateTime.Now - _portMapAt > TimeSpan.FromSeconds(3))
        {
            _portMapAt = DateTime.Now;
            _portMapRunning = true;
            Task.Run(() => { try { PortMap.Apply(_engine.Store); } catch { } finally { _portMapRunning = false; } });
        }
        if (_showInk && !_grid.Columns["Ink"]!.Visible) _grid.Columns["Ink"]!.Visible = true;
        if (_showPorts && !_grid.Columns["SwPort"]!.Visible) _grid.Columns["SwPort"]!.Visible = true;
        if (_cleared)
        {
            _cleared = false;
            _grid.Rows.Clear(); _rows.Clear(); _dirty.Clear(); _portsQueued.Clear();
            while (_removed.TryDequeue(out _)) { }
            SelectDevice(null);
            // devices found again between the clear and this refresh
            foreach (var d in _engine.Store.All) _dirty[d.Key] = d;
        }
        var fresh = new List<string>();
        while (_logQueue.TryDequeue(out var l)) fresh.Add(l);
        if (fresh.Count > 0)
        {
            _logAll.AddRange(fresh);
            if (_logAll.Count > 20_000) _logAll.RemoveRange(0, _logAll.Count - 15_000);
            var show = _logFilter == null ? fresh : fresh.Where(l => _logFilter.IsMatch(l)).ToList();
            if (show.Count > 0)
            {
                _logShown += show.Count;
                if (_log.TextLength > 400_000) UpdateLogView(force: true);
                else { _log.AppendText(string.Join("\r\n", show) + "\r\n"); if (_logFilter != null) ShowLogInfo(); }
            }
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
        ProcessWatch();
        if (_dirty.IsEmpty && !changed)
        {
            if (_revealing && DateTime.Now - _revealFrom > RevealPause) EndReveal();
            RefreshSelected();
            return;
        }

        var sortCol = _grid.SortedColumn; var sortDir = _grid.SortOrder;
        var keys = _dirty.Keys.ToList();
        if (_revealing)
        {
            // rows already shown are updated; new ones wait for their turn (lowest IP first)
            var waiting = keys.Where(k => !_rows.ContainsKey(k)).ToList();
            var take = DateTime.Now - _revealFrom < RevealPause ? 0 : Math.Max(1, (int)Math.Ceiling(_engine.Store.Count / 20.0));
            var next = waiting.Select(k => (k, d: _engine.Store.Find(k))).OrderBy(x => x.d?.Ip == null ? long.MaxValue : IpKey(x.d.Ip.ToString()))
                .Take(take).Select(x => x.k).ToHashSet();
            keys = keys.Where(k => _rows.ContainsKey(k) || next.Contains(k)).ToList();
            if (take > 0 && waiting.Count <= take) EndReveal();
        }
        foreach (var key in keys)
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
            FollowWatchedMac(d);
            if (_reselect == key && row.Visible)
            {
                _reselect = null;
                _grid.ClearSelection();
                row.Selected = true;
                SetCurrent(row);
            }
        }
        if (sortCol != null && sortDir != SortOrder.None)
            _grid.Sort(sortCol, sortDir == SortOrder.Ascending ? System.ComponentModel.ListSortDirection.Ascending : System.ComponentModel.ListSortDirection.Descending);
        // the grid marks the first row it gets as selected by itself; with no device picked, show none
        if (_selected == null && _grid.SelectedRows.Count > 0) _grid.ClearSelection();
        UpdateCounters();
        RefreshSelected();
    }

    private void UpdateCounters()
    {
        int total = 0, mine = 0, other = 0, routed = 0, risky = 0;
        var kinds = new Dictionary<string, int>();
        foreach (var r in _rows.Values)
        {
            if (r.Tag is not Device d) continue;
            total++;
            lock (d)
            {
                if (PortRisk.Risky(d.OpenPorts).Count > 0) risky++;
                var k = Category(d);
                kinds[k] = kinds.GetValueOrDefault(k) + 1;
                if (d.IsSelf) { mine++; continue; }
                if (d.Ip == null) continue;
                if (d.Routed) routed++;
                else if (d.Reachable) mine++;
                else other++;
            }
        }
        foreach (var i in _nav.Items)
        {
            if (i.IsSection) continue;
            i.Count = i.Key switch
            {
                "all" => total, "net:mine" => mine, "net:other" => other, "net:routed" => routed,
                "watch" => _watchList.Count, "risky" => risky,
                _ => kinds.GetValueOrDefault(i.Key),
            };
        }
        if (_nav.Find("net:routed") is { } rt) rt.Hidden = routed == 0 && _nav.SelectedKey != "net:routed";
        if (_nav.Find("net:other") is { } ot) ot.Sub = _engine.CaptureAvailable || _demo ? T("found by listening") : T("needs Npcap to see them");
        if (_nav.Find("watch") is { } wt)
        {
            var states = _watcher.States.Select(x => { lock (x) return x.Health; }).ToList();
            var down = states.Count(h => h == Health.Down);
            wt.Sub = _watchList.Count == 0 ? T("pick devices…") : down > 0 ? T($"{down} down") : states.Any(h => h == Health.Unknown) ? T("checking…") : T($"all up · every {Dialogs.EveryText(_settings.WatchSeconds)}");
            wt.SubBad = down > 0;
        }
        _nav.Invalidate();
        _stCount.Text = T($"{total} devices  ·  {mine} my subnet  ·  {other} other subnets") + (routed > 0 ? T($"  ·  {routed} routed") : "");
        UpdateSummary();
    }

    /// <summary>"16 found · scan finished 21:11 · still listening for new devices", next to the list title.</summary>
    private void UpdateSummary()
    {
        var shown = _rows.Values.Count(r => r.Visible);
        var all = _nav.SelectedKey == "all" && _txtFilter.Text.Trim().Length == 0;
        var parts = new List<string> { !all ? T($"{shown} shown") : _scanCts != null && _startedEmpty ? T($"{shown} answered so far") : T($"{shown} found") };
        if (_scanCts != null) parts.Add(_startedEmpty ? T("new scan: the list started empty, scanning…") : T("scanning…"));
        else if (_lastScan is { } t)
        {
            parts.Add(T($"scan finished {t:HH:mm}"));
            var gone = Gone().Count;
            if (gone > 0) parts.Add(T($"{gone} of the last list did not answer"));
        }
        if (_btnListen.Checked) parts.Add(T("still listening for new devices"));
        _summary.Text = string.Join("  ·  ", parts);
    }

    /// <summary>The side-menu group of a device (call inside lock).</summary>
    private static string Category(Device d)
    {
        if (d.IsSelf) return "pc";
        if (d.EffectiveType == DeviceTypes.WindowsPc && Regex.IsMatch(d.Info.GetValueOrDefault("Windows") ?? "", @"\bServer\b", RegexOptions.IgnoreCase)) return "server";
        return d.EffectiveType switch
        {
            DeviceTypes.WindowsPc or DeviceTypes.Mac => "pc",
            DeviceTypes.Linux or DeviceTypes.Vm or DeviceTypes.WindowsServer => "server",
            DeviceTypes.Camera or DeviceTypes.Nvr => "camera",
            DeviceTypes.Printer => "printer",
            DeviceTypes.Router or DeviceTypes.Switch or DeviceTypes.AccessPoint or DeviceTypes.Firewall => "network",
            DeviceTypes.Nas => "storage",
            DeviceTypes.Android or DeviceTypes.IPhone or DeviceTypes.Phone or DeviceTypes.Tv or DeviceTypes.Console => "phone",
            _ => "other",
        };
    }

    /// <summary>Which "Networks" item of the side menu a device is under (call inside lock).</summary>
    private static string NetKey(Device d) =>
        d.IsSelf ? "net:mine" : d.Ip == null ? "" : d.Routed ? "net:routed" : d.Reachable ? "net:mine" : "net:other";

    private bool NavMatches(Device d)
    {
        var key = _nav.SelectedKey;
        if (key == "all") return true;
        lock (d)
            return key switch
            {
                "watch" => d.Ip != null && _watcher.Get(d.Ip.ToString()) != null,
                "risky" => PortRisk.Risky(d.OpenPorts).Count > 0,
                _ => key.StartsWith("net:") ? NetKey(d) == key : Category(d) == key,
            };
    }

    private void FillRow(DataGridViewRow row, Device d)
    {
        var P = Theme.P;
        lock (d)
        {
            row.Cells["Type"].Value = d.IsSelf ? Theme.ThisPc : d.EffectiveType;
            row.Cells["Ip"].Value = d.Ip?.ToString() ?? T("(unknown)");
            row.Cells["Open"].Value = T(PrimaryFor(d)?.Label ?? "");
            row.Cells["Name"].Value = d.DisplayName.Length == 0 || d.DisplayName == d.Model ? "–" : d.DisplayName;
            row.Cells["Model"].Value = d.Model ?? "";
            row.Cells["Model"].ToolTipText = d.ModelSource != null ? T("Model from ") + d.ModelSource : T(d.Info.GetValueOrDefault("Windows status"));
            row.Cells["Vendor"].Value = ShortVendor(d.Info.GetValueOrDefault("Manufacturer") ?? d.Vendor);
            row.Cells["Vendor"].ToolTipText = d.Vendor ?? "";
            row.Cells["Mac"].Value = d.Mac.Length > 0 ? d.Mac : "—";
            row.Cells["Net"].Value = NetText(d);
            var ports = d.PortsCheckedAt == null ? (d.OpenPorts.Count > 0 ? string.Join(", ", d.OpenPorts) : "") : d.OpenPorts.Count == 0 ? T("none") : string.Join(", ", d.OpenPorts);
            var risky = PortRisk.Risky(d.OpenPorts);
            row.Cells["Ports"].Value = risky.Count > 0 ? "⚠ " + ports : ports;
            row.Cells["Ports"].Style.ForeColor = risky.Count > 0 ? P.Bad : Color.Empty;
            row.Cells["Ports"].Style.Font = risky.Count > 0 ? Theme.Bold : null;
            row.Cells["Ports"].ToolTipText = string.Join("\n", risky.Select(f => $"{f.Port} {T(f.Service)}: {T(f.Advice)}"));
            row.Cells["Watch"].Value = WatchText(d.Ip?.ToString());
            var pr = d.Printer;
            row.Cells["Ink"].Value = pr == null ? "" : string.Join(" · ", Ink.Shown(pr).Select(Ink.Text));
            row.Cells["Ink"].ToolTipText = pr == null ? "" : string.Join("\n", pr.Supplies.Select(x => x.Text + (x.Detail != null ? $"  ({x.Detail})" : ""))) +
                (pr.Pages is { } pages ? T($"\n{pages:N0} pages printed") : "") + (pr.Status != null ? T($"\nStatus: {T(pr.Status)}") : "");
            row.Cells["SwPort"].Value = SpotText(d.Info.GetValueOrDefault(PortMap.PortKey));
            if (pr is { Supplies.Count: > 0 }) _showInk = true;
            if (d.Switch != null) _haveSwitches = true;
            if (d.Info.ContainsKey(PortMap.PortKey)) _showPorts = true;
            row.Cells["Via"].Value = string.Join(", ", d.Sources);
            row.Cells["Seen"].Value = d.LastSeen.ToString("HH:mm:ss");
            var otherNet = d.Ip != null && !d.Reachable;
            row.DefaultCellStyle.BackColor = otherNet ? P.OtherRow : P.Surface;
            row.Cells["Net"].Style.ForeColor = otherNet ? P.Warn : P.Good;
            row.Cells["Net"].Style.Font = otherNet ? Theme.Bold : Theme.Base;
        }
        SetVisible(row, MatchesFilter(row));
    }

    internal static string ShortVendor(string? v) => Core.Export.DeviceText.ShortVendor(v);

    private void SetVisible(DataGridViewRow row, bool visible)
    {
        if (row.Visible == visible) return;
        if (!visible && _grid.CurrentRow == row) _grid.CurrentCell = null;
        row.Visible = visible;
    }

    private bool MatchesFilter(DataGridViewRow row)
    {
        if (row.Tag is not Device d) return true;
        if (!NavMatches(d)) return false;
        var f = _txtFilter.Text.Trim();
        if (f.Length == 0) return true;
        return row.Cells.Cast<DataGridViewCell>().Any(c => c.Value?.ToString()?.Contains(f, StringComparison.OrdinalIgnoreCase) == true) ||
               (d.Vendor?.Contains(f, StringComparison.OrdinalIgnoreCase) ?? false);
    }

    private void ApplyFilter()
    {
        foreach (var row in _rows.Values) SetVisible(row, MatchesFilter(row));
        UpdateSummary();
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
        if (force) _stState.Text = T($"Checking ports of {d.Ip}…");
        await _portSem.WaitAsync();
        try { await Task.Run(() => _engine.CheckPortsAsync(d, _lifetime.Token)); }
        catch { }
        finally { _portSem.Release(); }
        if (force && !IsDisposed) _stState.Text = T($"Ports of {d.Ip}: {(d.OpenPorts.Count == 0 ? T("none open") : string.Join(", ", d.OpenPorts))}");
    }

    // ───────────────────────────── device tab ─────────────────────────────

    private Device? SelectedDevice() => _grid.SelectedRows.Count > 0 ? _grid.SelectedRows[0].Tag as Device : null;

    private void SelectDevice(Device? d)
    {
        _selected = d;
        _selectedRev = -1;
        _panelSig = "";
        RefreshSelected();
        UpdateLogView();
    }

    /// <summary>Fills the Log tab: the lines about the selected device (its IP, MAC or name), or the whole log.</summary>
    private void UpdateLogView(bool force = false)
    {
        var d = _logOnlySel.Checked ? _selected : null;
        if (!force && d == _logFor && (d != null || _logFilter == null) && _log.TextLength > 0) return;
        _logFor = d;
        _logFilter = d == null ? null : LogFilter.For(d);
        var lines = _logFilter == null ? _logAll : _logAll.Where(l => _logFilter.IsMatch(l)).ToList();
        _logShown = lines.Count;
        _log.Text = lines.Count == 0 ? "" : string.Join("\r\n", lines.Skip(Math.Max(0, lines.Count - 5000))) + "\r\n";
        _log.SelectionStart = _log.TextLength;
        _log.ScrollToCaret();
        ShowLogInfo();
    }

    private void ShowLogInfo()
    {
        _tabs.SetText(2, _logShown > 0 ? T($"Log ({_logShown})") : T("Log"));
        var d = _logFor;
        if (d == null || _logFilter == null)
        {
            _logInfo.Text = _selected == null || !_logOnlySel.Checked ? T("Whole log") + (_selected == null ? T("  (select a device to see only its lines)") : "") : T("Whole log");
            return;
        }
        string who;
        lock (d) who = d.IsSelf ? T("this PC") : d.Ip?.ToString() ?? d.DisplayName;
        _logInfo.Text = _logShown == 0 ? T($"No lines about {who} yet  (untick the box to see the whole log)") : T($"{_logShown} line(s) about {who}");
    }

    private void RefreshSelected()
    {
        var d = _selected;
        if (d == null) { if (_selectedRev != -2) { ShowEmptyDevicePanel(); _details.Rows.Clear(); FitDetails(); _selectedRev = -2; } return; }
        int rev;
        lock (d) rev = d.Revision;
        if (rev == _selectedRev) return;
        _selectedRev = rev;
        // Only rebuild when something visible changed (devices update on every packet).
        string sig;
        lock (d) sig = string.Join("|", d.DisplayName, d.EffectiveType, d.TypeReason, d.Reachable, d.Mac, d.Ip, d.BehindNvr, d.Routed, d.Model, d.ModelSource, string.Join(",", d.OpenPorts),
            string.Join(",", d.PortInfo.Values), d.PortsCheckedAt, d.Vendor, d.Info.Count, string.Join(",", d.Info.Values), d.Services.Count, d.Sources.Count, d.TypeOverride,
            d.Printer?.ReadAt, d.Switch?.ReadAt, d.SnmpTriedAt, _snmpBusy.Contains(d));
        sig += "|" + WatchText(d.Ip?.ToString()) + "|" + _settings.WatchSeconds;
        if (sig == _panelSig) return;
        _panelSig = sig;
        RenderDevicePanel(d);
        RenderDetails(d);
    }

    private static void ClearPanel(Control panel)
    {
        var old = panel.Controls.Cast<Control>().ToList();
        panel.Controls.Clear();
        foreach (var c in old) c.Dispose();
    }

    private void ShowEmptyDevicePanel()
    {
        _detailsHead.Show(null, T("No device selected"), T("Pick a device in the list to see how to open it, its model and its hardware."));
        _devicePanel.SuspendLayout();
        ClearPanel(_devicePanel);
        _devicePanel.Controls.Add(new Label
        {
            Text = T("Select a device in the list.\n\nDevices with an orange background are on a different subnet from this PC."),
            Dock = DockStyle.Fill, ForeColor = Theme.P.Muted, TextAlign = ContentAlignment.MiddleCenter,
        });
        _devicePanel.ResumeLayout();
    }

    private Label SectionLabel(string text, int top = 18) =>
        new() { Text = text.ToUpperInvariant(), Font = Theme.Section, ForeColor = Theme.P.Muted, AutoSize = true, Margin = new Padding(0, S(top), 0, S(6)), UseMnemonic = false };

    private void RenderDevicePanel(Device d)
    {
        var P = Theme.P;
        string title, sub, type, typeWhy; bool reachable, self, routed; IPAddress? ip; List<DeviceAction> actions;
        List<(int Port, string Info)> ports; DateTime? checkedAt; string? behindNvr, nvrChannel, nvrCount; bool nvrLike;
        string? model, modelSrc, serial, windows, winStatus; bool win, kerberos; var hw = new List<InfoTable.Row>();
        (string Label, DeviceAction Action)? primary;
        PrinterState? printer; SwitchState? sw; string? swPort, arpMac; DateTime? snmpTried; bool snmpAnswered, snmpKind;
        lock (d)
        {
            printer = d.Printer; sw = d.Switch; swPort = d.Info.GetValueOrDefault(PortMap.PortKey); arpMac = d.Info.GetValueOrDefault(PortMap.ArpMacKey);
            snmpTried = d.SnmpTriedAt; snmpAnswered = d.Sources.Contains("SNMP");
            snmpKind = !d.IsSelf && d.Ip != null && d.BehindNvr == null &&
                       d.EffectiveType is DeviceTypes.Printer or DeviceTypes.Switch or DeviceTypes.Router or DeviceTypes.AccessPoint;
            behindNvr = d.BehindNvr;
            nvrChannel = d.Info.GetValueOrDefault("NVR channel");
            nvrCount = d.Info.GetValueOrDefault("NVR cameras");
            nvrLike = behindNvr == null && !d.IsSelf && d.Ip != null &&
                      (d.EffectiveType is DeviceTypes.Nvr or DeviceTypes.Camera || nvrCount != null || d.OpenPorts.Contains(37777) ||
                       Regex.IsMatch(d.Vendor ?? "", "hikvision|dahua|hilook|annke|amcrest|lorex|uniview|tiandy|cp plus", RegexOptions.IgnoreCase));
            primary = PrimaryFor(d);
            ip = d.Ip;
            title = d.DisplayName.Length > 0 ? d.DisplayName : ip?.ToString() ?? d.Mac;
            sub = string.Join("  ·  ", new[] { d.DisplayName.Length > 0 && d.DisplayName != d.Model ? d.DisplayName : null, d.Mac.Length > 0 ? d.Mac : T("MAC unknown (behind a router)"), ShortVendor(d.Info.GetValueOrDefault("Manufacturer") ?? d.Vendor) }
                .Where(s => !string.IsNullOrEmpty(s)));
            type = d.EffectiveType;
            typeWhy = d.TypeOverride != null ? T("set by you") : d.TypeReason;
            reachable = d.Reachable; self = d.IsSelf; routed = d.Routed;
            actions = _engine.Plugins.ActionProviders.SelectMany(p => { try { return p.GetActions(d).ToList(); } catch { return new List<DeviceAction>(); } }).ToList();
            ports = d.OpenPorts.Select(p => (p, d.PortInfo.TryGetValue(p, out var s) ? s : "")).ToList();
            checkedAt = d.PortsCheckedAt;
            model = d.Model; modelSrc = d.ModelSource; serial = d.Info.GetValueOrDefault("Serial number"); windows = d.Info.GetValueOrDefault("Windows");
            winStatus = d.Info.GetValueOrDefault("Windows status");
            win = LooksWindows(d) || d.EffectiveType is DeviceTypes.WindowsPc or DeviceTypes.WindowsServer;
            kerberos = ServerSigns.IsKerberos(d);
            hw = HardwareRows(d);
        }
        var iconType = self ? Theme.ThisPc : type;
        _detailsHead.Show(iconType, self ? T("This PC") + (ip != null ? "  " + ip : "") : ip?.ToString() ?? title, sub);

        _panelWidth = _devicePanel.ClientSize.Width;
        var W = Math.Max(S(220), _devicePanel.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - S(4));
        _devicePanel.SuspendLayout();
        ClearPanel(_devicePanel);
        var flow = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = new Padding(0), Padding = new Padding(0, 0, 0, S(16)), Location = new Point(0, 0), BackColor = P.Surface };
        Label Text(string t, Font f, Color c, int top = 0, int bottom = 0) =>
            new() { Text = t, Font = f, ForeColor = c, AutoSize = true, MaximumSize = new Size(W, 0), Margin = new Padding(0, S(top), 0, S(bottom)), UseMnemonic = false };
        FlowLayoutPanel Buttons() => new() { AutoSize = true, WrapContents = true, MaximumSize = new Size(W + S(8), 0), Margin = new Padding(0, S(6), 0, 0), Padding = new Padding(0), BackColor = P.Surface };

        // model
        if (ip != null || self)
        {
            flow.Controls.Add(Text(model != null ? T($"Model · from {modelSrc}") : T("Model"), Theme.Base, P.Muted, 2));
            flow.Controls.Add(Text(model ?? T("Not known yet"), model != null ? Theme.Big : Theme.Header, model != null ? P.Text : P.Muted, 2));
            var extra = string.Join("  ·  ", new[] { serial != null ? "S/N " + serial : null, windows }.Where(x => x != null));
            if (extra.Length > 0) flow.Controls.Add(Text(extra, Theme.Base, P.Muted, 3));
            if (winStatus != null)
                flow.Controls.Add(new Label
                {
                    Text = "⚠  " + T(winStatus) + (winStatus.StartsWith("Firewall") ? T(": Windows did not let us read it. The fix is in the Log tab.") : ""),
                    AutoSize = true, MaximumSize = new Size(W, 0), BackColor = P.WarnSoft, ForeColor = P.Warn, Font = Theme.Bold, UseMnemonic = false,
                    Padding = new Padding(S(8), S(4), S(8), S(4)), Margin = new Padding(0, S(8), 0, 0),
                });
            var mb = Buttons();
            if (!self)
            {
                var get = MakeButton(T("Get model"));
                new ToolTip().SetToolTip(get, T("Ask the device (web page, UPnP, SNMP, ONVIF, IPP) – no password needed"));
                get.Click += async (_, _) => await GetModelAsync(d);
                mb.Controls.Add(get);
            }
            if (win)
            {
                var wmi = MakeButton(self ? T("Read this PC's model") : hw.Count > 0 ? T("Read again (Windows login)…") : T("Windows login…"));
                new ToolTip().SetToolTip(wmi, T("Model, serial number, CPU, RAM, disks, graphics card and Windows version, read from Windows itself (needs an admin login on that PC)"));
                wmi.Click += async (_, _) => await GetWindowsModelAsync(d, askLogin: !self);
                mb.Controls.Add(wmi);
            }
            if (mb.Controls.Count > 0) flow.Controls.Add(mb);
        }

        // printer: toner / ink levels; switch: its ports (SNMP)
        if (printer != null) RenderPrinter(flow, d, printer, W, Text, Buttons);
        if (sw is { IsBridge: true }) RenderSwitch(flow, d, sw, W, Text, Buttons);
        if (snmpKind && printer == null && sw is not { IsBridge: true }) RenderSnmpAsk(flow, d, type, snmpTried, snmpAnswered, W, Text, Buttons);

        // reachability + open
        if (ip == null)
            flow.Controls.Add(Text(T("IP address not known yet: this device was only heard by its MAC address (LLDP / DHCP). Press Scan or wait a little; as soon as it has an IP, the buttons to open it appear here."),
                Theme.Bold, P.Warn, 8, 6));
        if (ip != null && !self)
        {
            flow.Controls.Add(SectionLabel(T("Open")));
            var reach = Buttons();
            if (reachable)
            {
                flow.Controls.Add(Text(routed ? T("✔  Reachable through your router: you can open it directly.") : T("✔  Same subnet as this PC: you can open it directly."), Theme.Bold, P.Good));
                if (primary is { } pr)
                {
                    var openBtn = MakeButton(T("Open  ") + T(pr.Label), primary: true);
                    openBtn.Click += async (_, _) => await RunAction(d, pr.Action);
                    reach.Controls.Add(openBtn);
                }
            }
            else if (behindNvr != null)
            {
                flow.Controls.Add(Text(T($"Recorded by NVR {behindNvr}{ChannelSuffix(nvrChannel)}. Its IP is on the NVR's own camera network, so this PC can't open it directly: open it from the NVR's web page."), Theme.Bold, P.Warn));
                var nvrBtn = MakeButton(T("Open NVR web page"), primary: true);
                nvrBtn.Click += async (_, _) => await OpenNvrAsync(behindNvr);
                reach.Controls.Add(nvrBtn);
                var tryBtn = MakeButton(T("Try a temporary IP"));
                new ToolTip().SetToolTip(tryBtn, T("Works only if the camera is on the same cable/switch as this PC (not on the NVR's PoE ports)"));
                tryBtn.Click += async (_, _) => await MakeReachableAsync(d);
                reach.Controls.Add(tryBtn);
            }
            else
            {
                flow.Controls.Add(Text(T($"⚠  On another subnet ({Subnet.Of(ip, _settings.ReachPrefix)}). To open it, this PC needs a temporary IP in that subnet."), Theme.Bold, P.Warn));
                var btn = MakeButton(T("Make reachable"), primary: true);
                btn.Click += async (_, _) => await MakeReachableAsync(d);
                reach.Controls.Add(btn);
            }
            // the device's own actions (web, remote desktop, files, ping…)
            foreach (var a in actions)
            {
                var b = MakeButton(T(a.Title));
                new ToolTip().SetToolTip(b, (a.Group.Length > 0 ? T(a.Group) + ": " : "") + T(a.Tooltip ?? a.Title));
                b.Click += async (_, _) => await RunAction(d, a);
                reach.Controls.Add(b);
            }
            if (actions.Any(a => a.Group == "Web"))
            {
                var port = new InputBox(72) { Margin = new Padding(0, S(4), S(6), S(4)) };
                port.Box.PlaceholderText = T("port");
                port.Height = S(32);
                var go = MakeButton(T("Open port"));
                go.Click += async (_, _) =>
                {
                    if (!int.TryParse(port.Box.Text, out var p) || p is < 1 or > 65535 || ip == null) return;
                    var scheme = p is 443 or 8443 or 4443 or 9443 ? "https" : "http";
                    await RunAction(d, new DeviceAction("Web", $"{scheme}://{ip}:{p}", () => Core.Actions.Launcher.Open($"{scheme}://{ip}:{p}/")));
                };
                reach.Controls.Add(port);
                reach.Controls.Add(go);
            }
            if (reach.Controls.Count > 0) flow.Controls.Add(reach);
        }

        // which switch port it is plugged into
        if (swPort != null)
        {
            flow.Controls.Add(SectionLabel(T("Plugged into")));
            flow.Controls.Add(Text("🔌  " + SpotText(swPort), Theme.Bold, P.Text));
            if (Regex.Match(swPort, @"\((\d+) devices\)$") is { Success: true } many)
                flow.Controls.Add(Text(T($"{many.Groups[1].Value} devices are learned on this port: another switch or a Wi-Fi access point is plugged in there, and this device is behind it."), Theme.Small, P.Muted, 3));
            if (arpMac != null) flow.Controls.Add(Text(T($"MAC {arpMac}, from the router's ARP table."), Theme.Small, P.Muted, 3));
            var spot = PortMap.Locate(d.Mac.Length > 0 ? d.Mac : arpMac ?? "", PortMap.Switches(_engine.Store.All), d);
            if (spot != null)
            {
                var pb = Buttons();
                var show = MakeButton(T("Show the switch"));
                show.Click += (_, _) => { if (spot.Switch.Ip is { } sip) SelectIp(sip.ToString()); };
                pb.Controls.Add(show);
                flow.Controls.Add(pb);
            }
        }

        // watch (ping monitor)
        if (ip != null && !self)
        {
            flow.Controls.Add(SectionLabel(T("Watch")));
            var ws = _watcher.Get(ip.ToString());
            var wb = Buttons();
            if (ws != null)
            {
                Health h; DateTime since; DateTime? last; long? ms; string via;
                lock (ws) { h = ws.Health; since = ws.Since; last = ws.LastCheck; ms = ws.Ms; via = ws.Via; }
                var line = h switch
                {
                    Health.Up => T($"●  Up{(ms is { } m ? $" · {Ms(m)}" : "")}") + (via.StartsWith("port") ? T($" (answers on {via}, not to ping)") : ""),
                    Health.Down => T($"●  Down since {since:HH:mm}  ({Ago(since)})"),
                    _ => T("●  Checking…"),
                };
                flow.Controls.Add(Text(line, Theme.Bold, h == Health.Down ? P.Bad : h == Health.Up ? P.Good : P.Muted));
                flow.Controls.Add(Text(T($"Pinged every {Dialogs.EveryText(_settings.WatchSeconds)}") + (last is { } t ? T($", last check {t:HH:mm:ss}.") : "."), Theme.Base, P.Muted, 2));
                var stop = MakeButton(T("Stop watching"));
                stop.Click += (_, _) => ToggleWatch(d);
                wb.Controls.Add(stop);
            }
            else
            {
                flow.Controls.Add(Text(T("Get a message when this device stops answering, and when it comes back."), Theme.Base, P.Muted));
                var start = MakeButton(T("Watch this device"));
                start.Click += (_, _) => ToggleWatch(d);
                wb.Controls.Add(start);
            }
            var pick = MakeButton(T("Watch devices…"));
            pick.Click += (_, _) => PickWatched();
            wb.Controls.Add(pick);
            flow.Controls.Add(wb);
        }

        // NVR / DVR: list its cameras
        if (nvrLike)
        {
            flow.Controls.Add(SectionLabel(T("NVR / DVR cameras")));
            flow.Controls.Add(Text(T("Log in with the NVR's user and password to list its cameras: channel, IP, model, online/offline (Hikvision, Dahua and their rebrands)."), Theme.Base, P.Muted));
            var nb = Buttons();
            var cams = MakeButton(nvrCount != null ? T($"Show cameras again ({nvrCount})") : T("Show cameras on this NVR…"));
            cams.Click += (_, _) => ShowCameras(d);
            nb.Controls.Add(cams);
            flow.Controls.Add(nb);
        }

        // hardware read from Windows
        if (hw.Count > 0)
        {
            var table = new InfoTable { Title = T("Hardware"), Margin = new Padding(0, S(18), 0, 0) };
            table.Rows.AddRange(hw);
            table.Fit(W);
            flow.Controls.Add(table);
        }

        // ports: what is open, what is closed, and what is risky
        flow.Controls.Add(SectionLabel(T("Ports")));
        var open = ports.Select(p => p.Port).ToHashSet();
        var findings = PortRisk.Check(open);
        if (checkedAt != null && ports.Count > 0)
        {
            var chips = new ChipList { Margin = new Padding(0, 0, 0, S(4)) };
            foreach (var (port, info) in ports)
            {
                if (findings.Any(f => f.Port == port && f.Level == PortRiskLevel.High)) chips.Bad.Add(chips.Chips.Count);
                chips.Chips.Add((port.ToString(), port == 88 && kerberos ? T("Kerberos (domain logins)") : PortName(port), info.Length > 0 ? info : null));
            }
            chips.Fit(W);
            flow.Controls.Add(chips);
        }
        else
            flow.Controls.Add(Text(checkedAt == null
                ? (reachable ? T("Not checked yet.") : T("Make the device reachable first, then check its ports."))
                : T($"No open ports found (checked {checkedAt:HH:mm:ss})."), Theme.Base, P.Muted));
        if (checkedAt != null)
        {
            var closed = PortRisk.KeyServices.Where(k => !open.Contains(k.Port)).Select(k => $"{T(k.Name)} {k.Port}").ToList();
            if (closed.Count > 0) flow.Controls.Add(Text(T("Closed: ") + string.Join("  ·  ", closed), Theme.Small, P.Muted, 4));
            flow.Controls.Add(Text(T($"Checked {checkedAt:HH:mm:ss}, {_settings.Ports.Count} common ports."), Theme.Small, P.Muted, 2));
        }
        foreach (var f in findings.Where(f => f.Level == PortRiskLevel.High))
        {
            var card = new InfoCard { Tone = InfoCard.Kind.Bad, Width = W, Margin = new Padding(0, S(8), 0, 0), Cursor = Cursors.Default };
            card.Title = T($"⚠  {T(f.Service)} is open (port {f.Port})");
            card.Body = T(f.Advice);
            flow.Controls.Add(card);
        }
        foreach (var f in findings.Where(f => f.Level == PortRiskLevel.Note))
            flow.Controls.Add(Text($"{T(f.Service)} ({f.Port}): {T(f.Advice)}", Theme.Small, P.Muted, 6));
        if (reachable && !self)
        {
            var pb = Buttons();
            var chk = MakeButton(checkedAt != null ? T("Check ports again") : T("Check ports"));
            chk.Click += async (_, _) => await CheckPortsAsync(d, force: true);
            pb.Controls.Add(chk);
            flow.Controls.Add(pb);
        }

        // type + name
        flow.Controls.Add(SectionLabel(T("Type and name")));
        if (!string.IsNullOrEmpty(typeWhy)) flow.Controls.Add(Text(T("Detected from: ") + typeWhy, Theme.Small, P.Muted, 0, 4));
        var edit = Buttons();
        var rename = MakeButton(T("Rename…"));
        rename.Click += (_, _) => Rename(d);
        var typeBox = new DropPicker { Width = S(220), Margin = new Padding(0, S(4), 0, S(4)) };
        typeBox.Items.Add(T("Type: automatic"));
        var typeKeys = DeviceTypes.All.Where(t => t != DeviceTypes.Unknown).ToList();
        foreach (var t in typeKeys) typeBox.Items.Add(T(t));
        lock (d) typeBox.SelectedIndex = d.TypeOverride is { } over && typeKeys.IndexOf(over) is >= 0 and var at ? at + 1 : 0;
        typeBox.SelectedIndexChanged += (_, _) => SetType(d, typeBox.SelectedIndex <= 0 ? null : typeKeys[typeBox.SelectedIndex - 1]);
        edit.Controls.Add(rename);
        edit.Controls.Add(typeBox);
        flow.Controls.Add(edit);

        _devicePanel.Controls.Add(flow);
        _devicePanel.ResumeLayout();
    }

    // ───────────────────────────── SNMP: printers and switches ─────────────────────────────

    /// <summary>Toner / ink bars (in each toner's color), pages printed, the printer's status and warnings.</summary>
    private void RenderPrinter(FlowLayoutPanel flow, Device d, PrinterState pr, int W, Func<string, Font, Color, int, int, Label> text, Func<FlowLayoutPanel> buttons)
    {
        var P = Theme.P;
        flow.Controls.Add(SectionLabel(T("Ink / toner")));
        if (pr.Supplies.Count > 0)
        {
            var table = new InfoTable { Margin = new Padding(0, 0, 0, 0), KeyWidth = 120 };
            foreach (var x in pr.Supplies)
            {
                var level = Ink.Level(x) + (x.Low ? (x.FillsUp ? T("  ·  replace it") : T("  ·  low")) : "");
                double? bar = x.Percent is { } pct ? pct / 100.0 : null;
                table.Rows.Add(new InfoTable.Row(Ink.Name(x), level, x.Detail, false, bar, x.FillsUp ? (x.Low ? P.Warn : P.Muted) : Ink.For(x.Color), x.Low));
            }
            table.Fit(W);
            flow.Controls.Add(table);
        }
        else flow.Controls.Add(text(T("The printer answers, but does not tell its toner / ink levels."), Theme.Base, P.Muted, 0, 0));
        var facts = string.Join("  ·  ", new[] { pr.Pages is { } pages ? T($"{pages:N0} pages printed") : null, pr.Status == null ? null : T(pr.Status) }.Where(x => x != null));
        if (facts.Length > 0) flow.Controls.Add(text(facts, Theme.Bold, P.Text, 8, 0));
        foreach (var a in pr.Alerts) flow.Controls.Add(text("⚠  " + T(a), Theme.Base, P.Warn, 3, 0));
        flow.Controls.Add(text(T($"Read over SNMP at {pr.ReadAt:HH:mm}."), Theme.Small, P.Muted, 4, 0));
        var b = buttons();
        var again = MakeButton(_snmpBusy.Contains(d) ? T("Reading…") : T("Read again"));
        again.Enabled = !_snmpBusy.Contains(d);
        again.Click += async (_, _) => await ReadSnmpAsync(d);
        b.Controls.Add(again);
        flow.Controls.Add(b);
    }

    /// <summary>The switch's ports as squares (green: a device, blue: several), and "Show ports…" for the full list.</summary>
    private void RenderSwitch(FlowLayoutPanel flow, Device d, SwitchState sw, int W, Func<string, Font, Color, int, int, Label> text, Func<FlowLayoutPanel> buttons)
    {
        var P = Theme.P;
        flow.Controls.Add(SectionLabel(T("Switch ports")));
        flow.Controls.Add(text(T($"{sw.Up} of {sw.Ports.Count} ports up  ·  {sw.MacCount} devices learned"), Theme.Bold, P.Text, 0, 6));
        var byMac = PortPeople.ByMac(_engine.Store.All);
        var grid = new PortGrid { Margin = new Padding(0, S(2), 0, 0) };
        foreach (var p in sw.Ports) grid.Ports.Add((p, PortPeople.Tip(p, byMac)));
        grid.Fit(W);
        grid.PortClicked += p => ShowSwitchPorts(d);
        flow.Controls.Add(grid);
        flow.Controls.Add(text(T("Green: a device  ·  Blue: several devices (another switch or Wi-Fi AP)  ·  Light green: link up, nothing learned  ·  Gray: nothing plugged in"), Theme.Small, P.Muted, 6, 0));
        flow.Controls.Add(text(T($"Read over SNMP at {sw.ReadAt:HH:mm}.") + (sw.Arp.Count > 0 ? T($" Its ARP table has {sw.Arp.Count} addresses.") : ""), Theme.Small, P.Muted, 3, 0));
        var b = buttons();
        var show = MakeButton(T("Show ports…"), primary: true);
        show.Click += (_, _) => ShowSwitchPorts(d);
        b.Controls.Add(show);
        var again = MakeButton(_snmpBusy.Contains(d) ? T("Reading…") : T("Read again"));
        again.Enabled = !_snmpBusy.Contains(d);
        again.Click += async (_, _) => await ReadSnmpAsync(d);
        b.Controls.Add(again);
        flow.Controls.Add(b);
    }

    /// <summary>A printer / switch that did not tell anything over SNMP yet: why, and a box for the SNMP community (saved for every device).</summary>
    private void RenderSnmpAsk(FlowLayoutPanel flow, Device d, string type, DateTime? tried, bool answered, int W, Func<string, Font, Color, int, int, Label> text, Func<FlowLayoutPanel> buttons)
    {
        var P = Theme.P;
        var what = type == DeviceTypes.Printer ? T("toner / ink levels") : type == DeviceTypes.Switch ? T("ports (which device is on which port)") : T("devices and ports");
        flow.Controls.Add(SectionLabel(type == DeviceTypes.Printer ? T("Ink / toner") : T("Ports (SNMP)")));
        var busy = _snmpBusy.Contains(d);
        var communities = string.Join(", ", _settings.SnmpCommunityList.Select(c => $"\"{c}\""));
        flow.Controls.Add(text(busy ? T("Reading over SNMP…") :
            tried == null ? T($"Not read yet. NetFinder reads its {what} over SNMP.") :
            answered ? T($"It answered over SNMP, but does not share its {what}.") :
            T($"No answer over SNMP with the community {communities}. SNMP may be off on the device, or it uses another community (like a password, set on the device's web page)."),
            Theme.Base, tried != null && !answered && !busy ? P.Warn : P.Muted, 0, 6));
        var row = buttons();
        var box = new InputBox(150) { Margin = new Padding(0, S(4), S(6), S(4)) };
        box.Box.Text = _settings.SnmpCommunities;
        box.Box.PlaceholderText = "public";
        var read = MakeButton(busy ? T("Reading…") : tried == null ? T("Read now") : T("Save and try again"), primary: true);
        read.Enabled = !busy;
        new ToolTip().SetToolTip(box.Box, T("SNMP read community. Several? Put a comma between them. Saved for all devices (also in ☰ → Settings)."));
        async Task Go()
        {
            var c = string.IsNullOrWhiteSpace(box.Box.Text) ? "public" : box.Box.Text.Trim();
            if (c != _settings.SnmpCommunities) { _settings.SnmpCommunities = c; if (!_demo) _settings.Save(); }
            await ReadSnmpAsync(d);
        }
        read.Click += async (_, _) => await Go();
        box.Box.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await Go(); } };
        row.Controls.Add(new Label { Text = T("Community:"), AutoSize = true, ForeColor = P.Muted, Margin = new Padding(0, S(12), S(6), 0) });
        row.Controls.Add(box);
        row.Controls.Add(read);
        flow.Controls.Add(row);
    }

    /// <summary>Reads toner levels / switch ports (and model) over SNMP now, for one device.</summary>
    private async Task ReadSnmpAsync(Device d)
    {
        if (!_snmpBusy.Add(d)) return;
        IPAddress? ip;
        bool reachable;
        lock (d) { ip = d.Ip; reachable = d.Reachable; d.Revision++; }
        try
        {
            if (ip == null) return;
            if (!reachable && Ui.Box(this, T($"{ip} is on another subnet. Add a temporary IP in its subnet to ask it? (If your router lets this PC reach it, SNMP may work without one: press Cancel to try anyway.)"),
                    AppInfo.Name, MessageBoxButtons.OKCancel, MessageBoxIcon.Question) == DialogResult.OK && !await MakeReachableAsync(d)) return;
            _stState.Text = T($"Reading {ip} over SNMP…");
            await Task.Run(() => new SnmpEnricher().EnrichAsync(d, new EnrichContext { Engine = _engine, Settings = _settings }, CancellationToken.None));
            PrinterState? pr; SwitchState? sw; bool answered;
            lock (d) { pr = d.Printer; sw = d.Switch; answered = d.Sources.Contains("SNMP"); }
            _stState.Text = !answered ? T($"{ip} did not answer over SNMP (community {_settings.SnmpCommunities}).") :
                pr != null ? $"{ip}: " + (pr.Supplies.Count > 0 ? string.Join(", ", Ink.Shown(pr).Select(Ink.Text)) : T("printer, no supply levels")) :
                sw is { IsBridge: true } ? T($"{ip}: {sw.Up} of {sw.Ports.Count} ports up, {sw.MacCount} devices learned") : T($"{ip} answered over SNMP.");
        }
        catch (Exception ex) { _stState.Text = T($"SNMP {ip}: {ex.Message}"); }
        finally
        {
            _snmpBusy.Remove(d);
            _engine.Store.Touch(d, _ => { });
        }
    }

    private void ShowSwitchPorts(Device d)
    {
        if (d.Switch == null) return;
        using var f = new SwitchPortsForm(d, _engine.Store.All, _ => { });
        if (f.ShowDialog(this) == DialogResult.OK && f.Picked is { } p) PickOnPort(p);
    }

    /// <summary>Picks in the list the device plugged into this port (the first one when there are several).</summary>
    private void PickOnPort(SwitchPort p)
    {
        var byMac = PortPeople.ByMac(_engine.Store.All);
        foreach (var m in p.Macs)
            if (byMac.TryGetValue(m, out var l) && l[0].Ip is { } ip)
            {
                _nav.Select("all");
                SelectIp(ip.ToString());
                return;
            }
        _stState.Text = T($"Port {p.Name}: the device(s) there are not in the list (MAC {string.Join(", ", p.Macs.Take(3))}).");
    }

    /// <summary>CPU, RAM, each disk (with an SSD / HDD chip), each drive (with how full it is), graphics: what Windows told (call inside lock).</summary>
    private static List<InfoTable.Row> HardwareRows(Device d)
    {
        var rows = new List<InfoTable.Row>();
        if (d.Info.GetValueOrDefault("CPU") is { } cpu) rows.Add(new("CPU", cpu));
        if (d.Info.GetValueOrDefault("RAM") is { } ram) rows.Add(new("RAM", ram));
        if (d.Info.GetValueOrDefault("Disk") is { } disk)
        {
            var disks = SplitDisks(disk);
            for (var i = 0; i < disks.Count; i++)
            {
                var m = Regex.Match(disks[i], @"^(?<name>.+?) \((?<parts>[^()]*)\)$");
                var name = m.Success ? m.Groups["name"].Value : disks[i];
                var parts = m.Success ? m.Groups["parts"].Value.Split(", ") : Array.Empty<string>();
                var chip = parts.Length > 0 ? string.Join(" · ", parts) : null;
                rows.Add(new(disks.Count > 1 ? T($"Disk {i + 1}") : T("Disk"), name, chip, parts.Any(p => p is "SSD" or "NVMe")));
            }
        }
        var drives = d.Info.GetValueOrDefault("Drives") is { } dv ? SplitDisks(dv) : d.Info.GetValueOrDefault("Drive C:") is { } c ? new List<string> { "C: " + c } : new();
        foreach (var dr in drives)
        {
            var m = Regex.Match(dr, @"^(?<l>[A-Za-z]:)\s+(?<t>[\d.,]+\s*[KMGT]B)\s*\((?<f>[\d.,]+\s*[KMGT]B) free\)");
            if (m.Success && Bytes(m.Groups["t"].Value) is > 0 and var total && Bytes(m.Groups["f"].Value) is var free)
                rows.Add(new(T("Drive ") + m.Groups["l"].Value.ToUpperInvariant(), T($"{m.Groups["f"].Value} free of {m.Groups["t"].Value}"), Bar: 1 - free / total));
            else rows.Add(new(T("Drive ") + dr.Split(' ')[0], dr[(dr.IndexOf(' ') + 1)..]));
        }
        if (d.Info.GetValueOrDefault("Graphics") is { } gpu) rows.Add(new(T("Graphics"), gpu));
        return rows;
    }

    /// <summary>"1.8 TB" → bytes.</summary>
    private static double Bytes(string s)
    {
        var m = Regex.Match(s.Replace(',', '.'), @"([\d.]+)\s*([KMGT])B");
        if (!m.Success || !double.TryParse(m.Groups[1].Value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var v)) return 0;
        return v * Math.Pow(1024, "KMGT".IndexOf(m.Groups[2].Value) + 1);
    }

    private static string PortName(int p) => T(PortRisk.Service(p));

    private RoundButton MakeButton(string text, bool primary = false) => new(text, primary);

    /// <summary>The window is built in one language; a new one is used from the next start.</summary>
    private void AskRestartForLanguage()
    {
        var next = Core.Text.L.Available().FirstOrDefault(l => l.Code == _settings.Language) ?? Core.Text.L.Builtin[0];
        // asked in both languages: the old one (what the user reads now) and the new one
        var text = T("Restart NetFinder now to show it in the new language?");
        using (Core.Text.L.Scope(next.Code)) { var other = T("Restart NetFinder now to show it in the new language?"); if (other != text) text += "\n\n" + other; }
        if (Ui.Box(this, text, next.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        Program.RestartRequested = true;
        Close();
    }

    /// <summary>"CORE-SW1 · port 7 (3 devices)" (kept in English in the device info) in the window's language.</summary>
    private static string SpotText(string? spot)
    {
        if (string.IsNullOrEmpty(spot)) return "";
        var m = Regex.Match(spot, @"^(?<sw>.*) · port (?<port>.+?)(?: \((?<n>\d+) devices\))?$");
        if (!m.Success) return spot;
        var text = T($"{m.Groups["sw"].Value} · port {m.Groups["port"].Value}");
        return m.Groups["n"].Success ? text + " " + T($"({m.Groups["n"].Value} devices)") : text;
    }

    private void RenderDetails(Device d)
    {
        _details.Rows.Clear();
        void Add(string k, string? v) { if (!string.IsNullOrEmpty(v)) _details.Rows.Add(new InfoTable.Row(k, v)); }
        lock (d)
        {
            Add(T("Type"), T(d.EffectiveType) + (d.TypeOverride != null ? T(" (set by you)") : ""));
            Add(T("Detected from"), d.TypeReason);
            Add(T("Name (yours)"), d.CustomName);
            Add(T("Hostname"), d.Hostname);
            Add(T("Model"), d.Model == null ? null : d.Model + (d.ModelSource != null ? T($"   (from {d.ModelSource})") : ""));
            Add(T("IP addresses"), string.Join(", ", d.Ips));
            Add("MAC", d.Mac);
            Add(T("Vendor"), d.Vendor);
            Add(T("Network"), d.Ip == null ? null : d.Routed ? T("Behind a router (reached by ping/TCP)") : d.Reachable ? T("Same subnet as this PC") :
                d.BehindNvr != null ? T($"On the camera network of NVR {d.BehindNvr}") : T("Other subnet: ") + Subnet.Of(d.Ip, 24));
            Add(T("Recorded by NVR"), d.BehindNvr);
            Add(T("Found via"), string.Join(", ", d.Sources));
            Add(T("Adapter"), _engine.AdapterById(d.AdapterId)?.FriendlyName);
            Add(T("First seen"), d.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss"));
            Add(T("Last seen"), d.LastSeen.ToString("yyyy-MM-dd HH:mm:ss"));
            Add(T("Open ports"), string.Join(", ", d.OpenPorts));
            foreach (var kv in d.PortInfo) Add(T($"Port {kv.Key}"), kv.Value);
            Add(T("Services (mDNS)"), string.Join(", ", d.Services));
            foreach (var kv in d.Info)
            {
                if (kv.Key == "Disk" && SplitDisks(kv.Value) is { Count: > 1 } disks)
                    for (var i = 0; i < disks.Count; i++) Add(T($"Disk {i + 1}"), disks[i]);
                else if (kv.Key == "Drives")
                    foreach (var dr in SplitDisks(kv.Value)) Add(T("Drive ") + dr.Split(' ')[0], dr[(dr.IndexOf(' ') + 1)..]);
                else Add(T(kv.Key), T(kv.Value));
            }
        }
        FitDetails();
    }

    private void FitDetails()
    {
        if (!_detailsPanel.Visible && _details.Width > 0) return;
        _details.Visible = _details.Rows.Count > 0;
        _details.Location = new Point(0, _detailsPanel.AutoScrollPosition.Y);
        _details.Fit(Math.Max(S(220), _detailsPanel.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - S(4)));
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
                var c = Ui.Box(this,
                    T($"{d.Ip} is recorded by NVR {nvr} and sits on the NVR's own camera network, so this PC can't open it directly.\n\n" +
                    $"Yes  =  open the NVR's web page (you can see and set up the camera from there)\n" +
                    $"No  =  try anyway with a temporary IP in its subnet"),
                    AppInfo.Name, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
                if (c == DialogResult.Cancel) return;
                if (c == DialogResult.Yes) { await OpenNvrAsync(nvr); return; }
                if (!await MakeReachableAsync(d)) return;
                try { a.Execute(); }
                catch (Exception ex) { Ui.Box(this, ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
                return;
            }
            var r = Ui.Box(this,
                T($"{d.Ip} is on another subnet, so this PC cannot talk to it yet.\n\nAdd a temporary IP in its subnet first? (It is removed when you close {AppInfo.Name}.)"),
                AppInfo.Name, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (r == DialogResult.Cancel) return;
            if (r == DialogResult.Yes && !await MakeReachableAsync(d)) return;
        }
        try { a.Execute(); }
        catch (Exception ex) { Ui.Box(this, ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
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
                return (T("via NVR"), new DeviceAction("NVR", T("Open NVR web page"), () => Launcher.Open($"http://{nvr}/")));
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
            if (hasIp) { _ = CheckPortsAsync(d, force: true); _stState.Text = T($"No open web/remote port known for {d.Ip}; checking its ports…"); }
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
            try { Launcher.Open($"http://{nvrIp}/"); } catch (Exception ex) { Ui.Box(this, ex.Message, AppInfo.Name); }
        }
    }

    private static string ChannelSuffix(string? nvrChannel)
    {
        var m = nvrChannel == null ? null : System.Text.RegularExpressions.Regex.Match(nvrChannel, @"channel (\d+)");
        return m is { Success: true } ? T($" (channel {m.Groups[1].Value})") : "";
    }

    private static string NetText(Device d) => d.IsSelf ? T("My subnet") : Core.Export.DeviceText.Network(d);

    /// <summary>"Show cameras": goes through RunAction so an NVR on another subnet is made reachable first.</summary>
    private void ShowCameras(Device? d)
    {
        if (d?.Ip == null) return;
        _ = RunAction(d, new DeviceAction("Tools", T("Show cameras"), () => ShowCamerasDialog(d)));
    }

    private void ShowCamerasDialog(Device d)
    {
        using var f = new NvrForm(_engine, d, dev => OpenPrimary(dev), url =>
        {
            if (IPAddress.TryParse(new Uri(url.Contains("://") ? url : "http://" + url).Host, out var ip) && _engine.Store.FindByIp(ip) is { } nvr)
                _ = RunAction(nvr, new DeviceAction("Web", url, () => Launcher.Open(url)));
            else
                try { Launcher.Open(url); } catch (Exception ex) { Ui.Box(this, ex.Message, AppInfo.Name); }
        });
        f.ShowDialog(this);
    }

    private async Task<bool> MakeReachableAsync(Device d)
    {
        UseWaitCursor = true;
        _stState.Text = T($"Adding a temporary IP to reach {d.Ip}…");
        try
        {
            var (ok, msg) = await _reach.MakeReachableAsync(d);
            _stState.Text = msg.Split('\n')[0];
            if (!ok) { Ui.Box(this, msg, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning); return false; }
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
        var name = Dialogs.Input(this, T("Rename device"), T($"Name for {d.Ip}{(d.Mac.Length > 0 ? $" ({d.Mac})" : "")}:"), current);
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

    private void Export(string ext)
    {
        var kind = ext switch { ".pdf" => T("PDF report"), ".csv" => T("CSV – opens in Excel"), ".html" => T("Web page"), _ => T("Excel workbook") };
        using var dlg = new SaveFileDialog
        {
            Title = T($"Export the {_rows.Values.Count(r => r.Visible)} devices shown"),
            Filter = $"{kind} (*{ext})|*{ext}",
            FileName = $"{AppInfo.Name}-{DateTime.Now:yyyyMMdd-HHmm}",
            DefaultExt = ext.TrimStart('.'),
            AddExtension = true,
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var path = dlg.FileName;
        if (!path.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) path += ext;
        try
        {
            // what the list shows (side menu + filter)
            var devices = _rows.Values.Where(r => r.Visible).Select(r => r.Tag).OfType<Device>().ToList();
            UseWaitCursor = true;
            try { Core.Export.Exporter.Save(path, devices, ExportTitle(), WatchExportText); }
            finally { UseWaitCursor = false; }
            _stState.Text = T($"Exported {devices.Count} devices to {path}");
            if (Ui.Box(this, T($"Saved {devices.Count} devices to\n{path}\n\nOpen it now?"), AppInfo.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                Launcher.Open(path);
        }
        catch (Exception ex)
        {
            Ui.Box(this, T("Could not save the file: ") + ex.Message + T($"\n\n(Is it open in {(ext == ".pdf" ? T("a PDF viewer") : T("Excel"))}? Close it and try again.)"), AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }


    // ───────────────────────────── watch devices ─────────────────────────────

    private readonly Dictionary<string, DateTime> _downSince = new();

    /// <summary>"Up · 3 ms", "Down · 4 min", "Checking…", or "" when the address is not watched.</summary>
    private Health WatchHealth(Device d)
    {
        string? ip;
        lock (d) ip = d.Ip?.ToString();
        var s = _watcher.Get(ip);
        if (s == null) return Health.Unknown;
        lock (s) return s.Health;
    }

    private string WatchText(string? ip)
    {
        var s = _watcher.Get(ip);
        if (s == null) return "";
        lock (s)
            return s.Health switch
            {
                Health.Up => s.Ms is { } ms ? T($"Up · {Ms(ms)}") : T("Up"),
                Health.Down => T($"Down · {Ago(s.Since)}"),
                _ => T("Checking…"),
            };
    }

    private static string Ms(long ms) => ms < 1 ? T("<1 ms") : T($"{ms} ms");

    private static string Ago(DateTime t)
    {
        var m = (DateTime.Now - t).TotalMinutes;
        return m < 1 ? T("just now") : m < 60 ? T($"{(int)m} min") : m < 48 * 60 ? T($"{(int)(m / 60)} h {(int)(m % 60)} min") : T($"{(int)(m / 1440)} days");
    }

    private static string Took(TimeSpan t) =>
        t.TotalMinutes < 1 ? $"{Math.Max(1, (int)t.TotalSeconds)} s" : t.TotalMinutes < 60 ? T($"{(int)t.TotalMinutes} min") : T($"{(int)t.TotalHours} h {t.Minutes} min");

    /// <summary>For the exports: "Up · 3 ms", "Down since 10:42".</summary>
    private string WatchExportText(Device d)
    {
        string? ip;
        lock (d) ip = d.Ip?.ToString();
        var s = _watcher.Get(ip);
        if (s == null) return "";
        lock (s)
            return s.Health switch
            {
                Health.Up => s.Ms is { } ms ? $"Up · {(ms < 1 ? "<1 ms" : $"{ms} ms")}" : "Up",
                Health.Down => $"Down since {(s.Since.Date == DateTime.Today ? s.Since.ToString("HH:mm") : s.Since.ToString("yyyy-MM-dd HH:mm"))}",
                _ => "Checking",
            };
    }

    /// <summary>Ports a device is known to have open, best first (for devices that ignore ping).</summary>
    private IReadOnlyCollection<int> OpenPortsFor(IPAddress ip)
    {
        var d = _engine.Store.FindByIp(ip);
        if (d == null) return Array.Empty<int>();
        int[] best = { 445, 3389, 80, 443, 22, 9100, 554, 8080, 135, 139 };
        lock (d) return d.OpenPorts.OrderBy(p => Array.IndexOf(best, p) is var i and >= 0 ? i : 100).ToList();
    }

    /// <summary>"Printer SHARP MX-3114N (10.0.0.201)".</summary>
    private string WatchLabel(string ip)
    {
        var d = _engine.Store.Find(ip);
        if (d != null)
            lock (d)
            {
                var name = d.DisplayName.Length > 0 ? d.DisplayName : d.Model ?? "";
                return $"{d.EffectiveType} {name} ({ip})".Replace("  ", " ");
            }
        var w = _watchList.FirstOrDefault(x => x.Ip == ip);
        return w != null && w.Name.Length > 0 ? $"{w.Name} ({ip})" : ip;
    }

    private void PickWatched()
    {
        var picks = new List<Dialogs.WatchPick>();
        var seen = new HashSet<string>();
        foreach (var row in _rows.Values.OrderBy(r => IpKey(r.Cells["Ip"].Value)))
        {
            if (row.Tag is not Device d) continue;
            lock (d)
            {
                if (d.IsSelf || d.Ip == null) continue;
                var ip = d.Ip.ToString();
                seen.Add(ip);
                picks.Add(new Dialogs.WatchPick(ip, d.Mac, d.DisplayName == d.Model ? "" : d.DisplayName, d.EffectiveType, d.Model ?? "", Category(d), _watcher.Get(ip) != null));
            }
        }
        foreach (var w in _watchList.Where(w => !seen.Contains(w.Ip)))
            picks.Add(new Dialogs.WatchPick(w.Ip, w.Mac, w.Name, T("(not in the list now)"), "", "", true));
        var choice = Dialogs.AskWatch(this, picks, _settings.WatchSeconds, _settings.WatchSound);
        if (choice == null) return;
        SetWatchList(choice.Devices.Select(p => new WatchItem { Ip = p.Ip, Mac = p.Mac, Name = p.Name.Length > 0 ? p.Name : p.Model }).ToList(), choice.Seconds, choice.Sound);
    }

    private void ToggleWatch(Device d)
    {
        WatchItem item;
        lock (d)
        {
            if (d.IsSelf || d.Ip == null) return;
            item = new WatchItem { Ip = d.Ip.ToString(), Mac = d.Mac, Name = d.DisplayName.Length > 0 ? d.DisplayName : d.Model ?? "" };
        }
        var list = _watchList.ToList();
        if (list.RemoveAll(w => w.Ip == item.Ip) == 0) list.Add(item);
        SetWatchList(list, _settings.WatchSeconds, _settings.WatchSound);
    }

    private void SetWatchList(List<WatchItem> items, int seconds, bool sound)
    {
        _watchList.Clear();
        _watchList.AddRange(items);
        _settings.WatchSeconds = seconds;
        _settings.WatchSound = sound;
        if (!_demo) _settings.Save(); // _watchList is _settings.Watch outside demo mode
        ApplyWatchList(log: true);
    }

    private void ApplyWatchList(bool log)
    {
        _watcher.Interval = TimeSpan.FromSeconds(_settings.WatchSeconds);
        _watcher.SetTargets(_watchList.Select(w => w.Ip));
        foreach (var ip in _downSince.Keys.Where(k => _watcher.Get(k) == null).ToList()) _downSince.Remove(ip);
        if (_watchList.Count > 0)
        {
            _watcher.Start();
            if (log) _engine.Log($"Watch: {_watchList.Count} device(s), ping every {Dialogs.EveryText(_settings.WatchSeconds)}: {string.Join(", ", _watchList.Select(w => w.Ip))}");
            if (!_demo) EnsureTray();
        }
        else
        {
            _watcher.Stop();
            if (log) _engine.Log("Watch: stopped (no devices picked)");
            if (_tray != null) _tray.Visible = false;
        }
        var watchCol = _grid.Columns["Watch"]!;
        if (_watchList.Count == 0 && _grid.CurrentCell?.OwningColumn == watchCol) SetCurrent(_grid.CurrentCell.OwningRow!);
        watchCol.Visible = _watchList.Count > 0;
        foreach (var row in _rows.Values)
            if (row.Tag is Device d) row.Cells["Watch"].Value = WatchText(d.Ip?.ToString());
        UpdateCounters();
        if (_nav.SelectedKey == "watch") ApplyFilter();
        _selectedRev = -1;
        UpdateTrayText();
    }

    /// <summary>Alerts and list updates for the watched devices (on the UI thread).</summary>
    private void ProcessWatch()
    {
        var any = false;
        while (_watchEvents.TryDequeue(out var ev)) { any = true; Announce(ev.State, ev.Before); }
        if (_watchChecked) { _watchChecked = false; any = true; }
        if (!any) return;
        foreach (var w in _watchList)
            if (_rows.TryGetValue(w.Ip, out var row)) row.Cells["Watch"].Value = WatchText(w.Ip);
        UpdateCounters();
        UpdateTrayText();
        _selectedRev = -1; // the device pane shows the watch state too
    }

    private void Announce(WatchState s, Health before)
    {
        Health now; DateTime since; long? ms;
        lock (s) { now = s.Health; since = s.Since; ms = s.Ms; }
        if (_watcher.Get(s.Ip) != s) return; // no longer watched
        var label = WatchLabel(s.Ip);
        if (now == Health.Down)
        {
            _downSince[s.Ip] = since;
            Alert(s.Ip, T($"Down: {label}"), before == Health.Unknown ? T("It does not answer.") : T($"Stopped answering at {since:HH:mm}."), bad: true);
        }
        else if (now == Health.Up && before == Health.Down)
        {
            var was = _downSince.Remove(s.Ip, out var t) ? T($" It was down for {Took(since - t)}.") : "";
            Alert(s.Ip, T($"Back up: {label}"), T($"Answers again{(ms is { } m ? $" ({Ms(m)})" : "")}.{was}"), bad: false);
        }
    }

    private void Alert(string ip, string title, string text, bool bad)
    {
        _engine.Log($"Watch: {title}. {text}");
        _stState.Text = $"{title}. {text}";
        if (_demo) return;
        if (_settings.WatchSound) (bad ? System.Media.SystemSounds.Hand : System.Media.SystemSounds.Asterisk).Play();
        EnsureTray();
        _trayIp = ip;
        _tray!.ShowBalloonTip(15000, title, text, bad ? ToolTipIcon.Warning : ToolTipIcon.Info);
        if (!ContainsFocus || WindowState == FormWindowState.Minimized) Native.Flash(this);
    }

    private void EnsureTray()
    {
        if (_tray == null)
        {
            _tray = new NotifyIcon { Icon = Icon };
            _tray.MouseClick += (_, e) => { if (e.Button == MouseButtons.Left) ShowFromTray(null); };
            _tray.BalloonTipClicked += (_, _) => ShowFromTray(_trayIp);
            var menu = new ContextMenuStrip { Renderer = _renderer };
            menu.Items.Add(T("Open NetFinder"), null, (_, _) => ShowFromTray(null));
            menu.Items.Add(T("Watch devices…"), null, (_, _) => { ShowFromTray(null); PickWatched(); });
            _tray.ContextMenuStrip = menu;
        }
        _tray.Visible = true;
        UpdateTrayText();
    }

    private void UpdateTrayText()
    {
        if (_tray == null) return;
        var down = _watcher.States.Count(x => { lock (x) return x.Health == Health.Down; });
        var t = T($"{AppInfo.Name}: watching {_watchList.Count} device(s)") + (down > 0 ? T($", {down} down") : "");
        _tray.Text = t.Length > 63 ? t[..63] : t;
    }

    private void ShowFromTray(string? ip)
    {
        if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
        Activate();
        if (ip == null || !_rows.TryGetValue(ip, out var row)) return;
        if (!row.Visible) { _txtFilter.Text = ""; _nav.Select("watch"); }
        if (!row.Visible) return;
        _grid.ClearSelection();
        row.Selected = true;
        SetCurrent(row);
        _grid.FirstDisplayedScrollingColumnIndex = 0;
    }

    /// <summary>When DHCP gives a watched device a new IP, the watch follows it (by its MAC).</summary>
    private void FollowWatchedMac(Device d)
    {
        if (_watchList.Count == 0) return;
        string mac; string? ip; bool reachable;
        lock (d) { mac = d.Mac; ip = d.Ip?.ToString(); reachable = d.Reachable; }
        if (mac.Length == 0 || ip == null || !reachable) return;
        var item = _watchList.FirstOrDefault(w => w.Mac.Equals(mac, StringComparison.OrdinalIgnoreCase));
        if (item == null || item.Ip == ip || _watchList.Any(w => w.Ip == ip)) return;
        if (_engine.Store.Find(item.Ip) is { } old && string.Equals(old.Mac, mac, StringComparison.OrdinalIgnoreCase)) return; // same device, several IPs
        _engine.Log($"Watch: {mac} moved from {item.Ip} to {ip}; watching the new IP");
        item.Ip = ip;
        if (!_demo) _settings.Save();
        ApplyWatchList(log: false);
    }

    // ───────────────────────────── export helpers ─────────────────────────────

    private string ExportTitle() => $"Network devices – {(_demo ? "IT-DESK01" : Environment.MachineName)} – {DateTime.Now:yyyy-MM-dd HH:mm}"; // exports stay in English

    /// <summary>Arabic / Hebrew text for the PDF: drawn by Windows (joined letters, right to left) as a sharp picture.</summary>
    private static Core.Export.PdfReport.Picture? PdfPicture(string text, double sizePt, bool bold)
    {
        try
        {
            const float scale = 4f; // pixels per point: about 290 dpi
            using var font = new Font("Segoe UI", (float)(sizePt * scale), bold ? FontStyle.Bold : FontStyle.Regular, GraphicsUnit.Pixel);
            var rtl = text.FirstOrDefault(char.IsLetter) is var c && Core.Export.PdfReport.IsComplex(c.ToString());
            using var fmt = new StringFormat(StringFormat.GenericTypographic) { FormatFlags = StringFormatFlags.NoWrap | (rtl ? StringFormatFlags.DirectionRightToLeft : 0) };
            SizeF size;
            using (var probe = new Bitmap(1, 1))
            using (var pg = Graphics.FromImage(probe))
                size = pg.MeasureString(text, font, PointF.Empty, fmt);
            var w = (int)Math.Ceiling(size.Width) + 8;
            var h = (int)Math.Ceiling(font.GetHeight()) + 4;
            using var bmp = new Bitmap(w, h, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp))
            {
                g.Clear(Color.Transparent);
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
                using var ink = new SolidBrush(Color.FromArgb(0x16, 0x20, 0x2C));
                g.DrawString(text, font, ink, new RectangleF(2, 1, w - 4, h - 2), fmt);
            }
            using var ms = new MemoryStream();
            bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
            return new Core.Export.PdfReport.Picture(ms.ToArray(), w / scale, h / scale);
        }
        catch { return null; }
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
            if (nvr != null) { Ui.Box(this, T($"{ip} is a camera on NVR {nvr}; its model comes from the NVR (Show cameras on the NVR)."), AppInfo.Name); return; }
            if (Ui.Box(this, T($"{ip} is on another subnet. Add a temporary IP in its subnet to ask it?"), AppInfo.Name, MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            if (!await MakeReachableAsync(d)) return;
        }
        _stState.Text = T($"Asking {ip} for its model…");
        await CheckPortsAsync(d, force: true);
        string? model, src;
        lock (d) { model = d.Model; src = d.ModelSource; }
        _stState.Text = model != null ? T($"{ip}: {model}  (from {src})") :
            T($"{ip} did not tell its model.") + (LooksWindowsLocked(d) ? T(" It looks like a Windows PC: try \"Get model with Windows login\".") : "");
    }

    private static bool LooksWindowsLocked(Device d) { lock (d) return LooksWindows(d); }

    /// <summary>Windows PC (or probably one): worth asking with a Windows login. A PC maker's MAC alone is not enough.</summary>
    private static bool LooksWindows(Device d) =>
        d.IsSelf || d.Info.ContainsKey("Windows") || d.OpenPorts.Contains(135) || d.OpenPorts.Contains(3389) ||
        (d.OpenPorts.Contains(445) && d.EffectiveType is DeviceTypes.WindowsPc or DeviceTypes.WindowsServer or DeviceTypes.Unknown or DeviceTypes.Vm) ||
        (d.EffectiveType is DeviceTypes.WindowsPc or DeviceTypes.WindowsServer or DeviceTypes.Vm or DeviceTypes.Unknown && d.Info.GetValueOrDefault("TTL") == "128") ||
        (d.EffectiveType is DeviceTypes.WindowsPc or DeviceTypes.WindowsServer && d.PortsCheckedAt != null && d.OpenPorts.Count == 0);

    /// <summary>
    /// Asked with the Windows login in "Get models": what looks like Windows, anything typed Windows PC, and a PC maker's
    /// network card (Dell, HP, Lenovo…) that is not clearly something else. Safe: the login is only sent where 135 or 445 answers.
    /// </summary>
    private static bool WindowsCandidate(Device d) =>
        d.BehindNvr == null && (LooksWindows(d) || d.EffectiveType is DeviceTypes.WindowsPc or DeviceTypes.WindowsServer ||
        (BuiltInClassifier.IsPcMaker(d.Vendor) && d.EffectiveType is DeviceTypes.Unknown or DeviceTypes.Linux or DeviceTypes.Vm));

    /// <summary>"10.0.0.6 (Dell)": an IP with its maker, for the Log and the summary.</summary>
    private static string WhoWithMaker(Device d)
    {
        lock (d)
        {
            if (d.IsSelf) return T("This PC");
            var v = d.Info.GetValueOrDefault("Manufacturer") ?? d.Vendor;
            var maker = v == null || v.StartsWith('(') ? null
                : Regex.IsMatch(v, @"^(hewlett|hp\b)", RegexOptions.IgnoreCase) ? "HP" : Regex.Match(v, @"^[A-Za-z0-9\-]+").Value;
            return $"{d.Ip}{(string.IsNullOrEmpty(maker) ? "" : $" ({maker})")}";
        }
    }

    /// <summary>The disks of one PC, as stored in its "Disk" info ("A  +  B").</summary>
    private static List<string> SplitDisks(string v) => v.Split("  +  ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    /// <summary>"CPU … · RAM 8 GB · Disk 1: … · Disk 2: … · C: … · Graphics: …", or null when Windows told none of it.</summary>
    private static string? HardwareLine(PcInfo i)
    {
        var l = new List<string>();
        if (i.Cpu != null) l.Add("CPU " + i.Cpu);
        if (i.RamBytes is > 0) l.Add(T($"RAM {Math.Round(i.RamBytes.Value / 1073741824.0)} GB"));
        if (i.Disks != null)
        {
            var disks = SplitDisks(i.Disks);
            l.AddRange(disks.Count > 1 ? disks.Select((x, n) => T($"Disk {n + 1}: {x}")) : disks.Select(x => T("Disk: ") + x));
        }
        else l.Add(T("Disk: not reported"));
        if (i.Drives != null) l.AddRange(SplitDisks(i.Drives));
        if (i.Graphics != null) l.Add(T("Graphics: ") + i.Graphics);
        return l.Count == 0 ? null : string.Join("  ·  ", l);
    }

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
            var r = Ui.Box(this, T($"{ip} is on another subnet. Add a temporary IP in its subnet first?"), AppInfo.Name, MessageBoxButtons.OKCancel, MessageBoxIcon.Question);
            if (r != DialogResult.OK || !await MakeReachableAsync(d)) return;
        }
        UseWaitCursor = true;
        var who = self ? T("This PC") : ip!.ToString();
        _stState.Text = T($"Reading the model of {(self ? T("this PC") : who)} from Windows…");
        try
        {
            var session = new WindowsLoginSession(self ? null : _winLogin?.User, _winLogin?.Password, DomainHint(), _engine.Log);
            var res = await WindowsReader.ReadAsync(ip?.ToString() ?? ".", self, session, _lifetime.Token);
            _engine.Store.Touch(d, x => { res.Info.ApplyTo(x); x.Info.Remove("Windows status"); });
            _engine.Log($"Windows {who}: {res.Info.Model ?? "model not reported"} (via {res.Info.Via}, login {res.Login}{(res.Note != null ? "; " + res.Note : "")})");
            if (HardwareLine(res.Info) is { } hwLine) _engine.Log($"Windows {who}: {hwLine}");
            _stState.Text = $"{who}: {res.Info.Model ?? T("model not reported")}";
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            var kind = ex is WinReadException w ? w.Kind : WinFail.Other;
            _engine.Log($"Windows {who}: {ex.Message}");
            if (StatusFor(kind, true, true, ex.Message) is { } st) _engine.Store.Touch(d, x => x.Info["Windows status"] = st);
            _stState.Text = T("Could not read the Windows model: ") + ex.Message.Split('\n')[0];
            Ui.Box(this, $"{who}: {ex.Message}.\n\n{WindowsAdvice(kind, single: true)}", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally { UseWaitCursor = false; }
    }

    /// <summary>The short reason shown in the Model column when Windows could not be read, or null (kept in English in the
    /// device info, shown translated).</summary>
    private static string? StatusFor(WinFail kind, bool seen, bool evidence, string message) => kind switch
    {
        WinFail.Closed when !seen => "Turned off?",
        WinFail.Closed when !evidence => "135 and 445 closed",
        WinFail.Closed or WinFail.Blocked => "Firewall blocks it",
        WinFail.BadLogin => "Wrong password",
        WinFail.AccessDenied or WinFail.NotAdmin => "Login refused",
        _ => message.StartsWith("skipped") ? null : "Could not read it",
    };

    private static string WmiFirewallGpo => T(
        "On the domain controller (Group Policy Management), in a policy linked to the PCs:\n" +
        "Computer Configuration › Policies › Windows Settings › Security Settings › Windows Defender Firewall with Advanced Security › " +
        "Inbound Rules › New Rule › Predefined: \"Windows Management Instrumentation (WMI)\" (or \"File and Printer Sharing\", port 445) › tick all › Allow the connection.\n" +
        "Then run gpupdate /force on the PCs (or restart them) and try again.");

    /// <summary>Run once as administrator on a PC whose firewall blocks remote management: turns on Windows' own WMI and file-sharing rules.</summary>
    /// <summary>Plain netsh lines: they work pasted into Command Prompt or PowerShell alike (the group names are the English Windows ones).</summary>
    internal static readonly string[] AllowRemoteCommands =
    {
        "netsh advfirewall firewall set rule group=\"Windows Management Instrumentation (WMI)\" new enable=yes",
        "netsh advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=yes",
    };

    /// <summary>What to do about a failure, in plain words.</summary>
    private static string WindowsAdvice(WinFail kind, bool single) => kind switch
    {
        WinFail.Closed or WinFail.Blocked =>
            (single ? T("Its firewall blocks remote management. ") : T("Their firewall blocks remote management. ")) +
            T($"Open it once on {(single ? T("that PC") : T("each of them"))}: Command Prompt as administrator there, then run these two lines (they are also in the Log tab):\n{string.Join("\n", AllowRemoteCommands)}\n") +
            T("If an antivirus has its own firewall, allow it there instead.\n\nFor all PCs at once instead: ") + WmiFirewallGpo,
        WinFail.BadLogin => T("Check the user name and password. In a domain, write the user as DOMAIN\\user (e.g. ALMADA\\administrator) or user@domain.local."),
        WinFail.AccessDenied or WinFail.NotAdmin => T("Use an account that is administrator on that PC: a domain admin (DOMAIN\\user or user@domain.local), " +
            "or the PC's own Administrator (PCNAME\\Administrator; Windows 10/11 block other local admin accounts remotely)."),
        _ => T("Details are in the Log tab."),
    };

    /// <summary>
    /// "Get models": every device on the list, on every range. Devices on other subnets get a temporary IP in their range
    /// (one per range), then each device is asked without a password; Windows PCs also with a Windows login when one is given.
    /// </summary>
    private async Task GetModelsForAllAsync()
    {
        var all = _engine.Store.All.Where(d => { lock (d) return d.Ip != null || d.IsSelf; }).ToList();
        if (all.Count == 0) { Ui.Box(this, T("The list is empty. Press Scan first."), AppInfo.Name); return; }
        int other, win;
        other = all.Count(d => { lock (d) return !d.Reachable && !d.IsSelf && d.BehindNvr == null; });
        win = all.Count(d => { lock (d) return WindowsCandidate(d); });
        var opt = Dialogs.AskModelsOptions(this, all.Count, other, win, _winLogin);
        if (opt == null) return;
        if (opt.Login != null) _winLogin = opt.Login;

        _modelsCts = new CancellationTokenSource();
        var ct = _modelsCts.Token;
        _btnModels.Text = T("Stop models");
        FitHeader();
        _stProgress.Visible = true;
        int done = 0, found = 0, windowsOk = 0;
        var errors = new List<string>();
        var winFails = new Dictionary<WinFail, List<string>>();
        var silent = new List<string>();   // only in Windows' ARP table: did not answer at all (turned off?)
        var noSign = new List<string>();   // a PC maker's card, 135 / 445 closed and nothing else says Windows
        var session = opt.Login != null ? new WindowsLoginSession(opt.Login.User, opt.Login.Password, DomainHint(), _engine.Log) { AllowServiceStart = opt.StartRemoteRegistry } : null;
        var selfSession = new WindowsLoginSession(null, null, null, _engine.Log);
        if (session != null)
            _engine.Log("Get models: Windows login " + (session.User == null ? T("= this PC's own login") : T($"\"{session.User}\", trying {string.Join(", ", session.Spellings.Select(s => $"\"{s}\""))}")));
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
                    _stState.Text = T($"Adding a temporary IP for {g.Key}…");
                    var (ok, msg) = await _reach.MakeReachableAsync(g.First());
                    if (!ok) errors.Add($"{g.Key}: {msg.Split('\n')[0]}");
                }
            }

            // 2) check the Windows login once, on a domain PC, before using it on dozens of PCs
            if (session?.User != null)
            {
                _stState.Text = T("Checking the Windows login…");
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
                    bool self, isWin, seen; IPAddress? ip;
                    lock (d) { self = d.IsSelf; ip = d.Ip; }
                    if (!self) await Task.Run(() => _engine.CheckPortsAsync(d, ct), ct);
                    lock (d) { isWin = WindowsCandidate(d); seen = !_engine.CaptureAvailable || d.Sources.Any(s => s != "ARP table"); }
                    var askedWindows = isWin && (self || session != null);
                    if (askedWindows)
                    {
                        var who = WhoWithMaker(d);
                        try
                        {
                            var res = await WindowsReader.ReadAsync(ip?.ToString() ?? ".", self, self ? selfSession : session!, ct);
                            _engine.Store.Touch(d, x => { res.Info.ApplyTo(x); x.Info.Remove("Windows status"); });
                            Interlocked.Increment(ref windowsOk);
                            _engine.Log($"Windows {who}: {res.Info.Model ?? "model not reported"} (via {res.Info.Via}, login {res.Login}{(res.Note != null ? "; " + res.Note : "")})");
                            if (HardwareLine(res.Info) is { } hwLine) _engine.Log($"Windows {who}: {hwLine}");
                        }
                        catch (OperationCanceledException) { throw; }
                        catch (Exception ex)
                        {
                            var kind = ex is WinReadException w ? w.Kind : WinFail.Other;
                            bool evidence; lock (d) evidence = LooksWindows(d);
                            // shown in the Model column of the list ("Firewall blocks it")
                            if (StatusFor(kind, seen, evidence, ex.Message) is { } st) _engine.Store.Touch(d, x => x.Info["Windows status"] = st);
                            if (kind == WinFail.Closed && !seen)
                            {
                                lock (silent) silent.Add(who);
                                _engine.Log($"Windows {who}: did not answer at all; it is only in Windows' ARP table (turned off, or no longer on the network)");
                            }
                            else if (kind == WinFail.Closed && !evidence)
                            {
                                lock (noSign) noSign.Add(who);
                                _engine.Log($"Windows {who}: ports 135 and 445 are closed and nothing else says it is Windows (a firewall that blocks everything, or not a PC: a server's management card, a thin client…)");
                            }
                            else
                            {
                                lock (winFails) { if (!winFails.TryGetValue(kind, out var l)) winFails[kind] = l = new(); l.Add(who); }
                                if (!ex.Message.StartsWith("skipped")) _engine.Log($"Windows {who}: {ex.Message}");
                            }
                        }
                    }
                    string? model, src, type; string openPorts;
                    lock (d) { model = d.Model; src = d.ModelSource; type = d.EffectiveType; openPorts = d.OpenPorts.Count == 0 ? T("none") : string.Join(", ", d.OpenPorts.OrderBy(p => p)); }
                    if (model != null) Interlocked.Increment(ref found);
                    // one line per device, so the Log tab of each device says what "Get models" found there
                    if (!askedWindows && !self && ip != null)
                        _engine.Log(model != null ? $"Get models {ip}: {model} (from {src})"
                            : $"Get models {ip}: it did not tell its model ({type}; open ports: {openPorts})" +
                              (isWin && session == null ? T("; it may be a Windows PC: tick \"Use a Windows login\" to read it") : ""));
                }
                finally
                {
                    sem.Release();
                    var n = Interlocked.Increment(ref done);
                    if (!IsDisposed) _stState.Text = T($"Getting models… {n}/{targets.Count}");
                }
            }));
            foreach (var e in errors) _engine.Log("Get models: " + e);
            var winFailed = winFails.Values.Sum(v => v.Count) + silent.Count + noSign.Count;
            _stState.Text = T($"Models: {found} of {targets.Count} devices have a model") +
                            (windowsOk + winFailed > 0 ? T($"  ·  Windows PCs: {windowsOk} read, {winFailed} not") : "") +
                            (errors.Count + winFailed > 0 ? T("  ·  details in the Log tab") : "");
            _stExport.Visible = true;
            if (winFailed + silent.Count + noSign.Count > 0) ShowWindowsSummary(windowsOk, winFails, silent, noSign, session?.StopReason);
        }
        catch (OperationCanceledException) { _stState.Text = T($"Get models stopped ({done} done)."); }
        finally
        {
            _modelsCts.Dispose(); _modelsCts = null;
            _btnModels.Text = T("Get models");
            FitHeader();
            _stProgress.Visible = _scanCts != null;
        }
    }

    /// <summary>One clear summary of the Windows part of "Get models": what worked, what blocked it, and how to fix it.</summary>
    private void ShowWindowsSummary(int ok, Dictionary<WinFail, List<string>> fails, List<string> silent, List<string> noSign, string? stopReason)
    {
        List<string> Get(params WinFail[] k) => k.SelectMany(x => fails.GetValueOrDefault(x) ?? new()).ToList();
        string Ips(List<string> l) => string.Join(", ", l.Take(12)) + (l.Count > 12 ? $" … (+{l.Count - 12})" : "");
        var closed = Get(WinFail.Closed);
        var blocked = Get(WinFail.Blocked);
        var denied = Get(WinFail.AccessDenied, WinFail.NotAdmin);
        var bad = Get(WinFail.BadLogin);
        var otherFail = Get(WinFail.Other);
        var lines = new List<string> { T($"Windows PCs read: {ok}.") };
        if (closed.Count > 0) lines.Add(T($"{closed.Count} PC(s) block every remote-management port (135 and 445 closed): {Ips(closed)}"));
        if (blocked.Count > 0) lines.Add(T($"{blocked.Count} PC(s) answer, but their firewall blocks WMI: {Ips(blocked)}"));
        if (denied.Count > 0) lines.Add(T($"{denied.Count} PC(s) refused the login (not an administrator there?): {Ips(denied)}"));
        if (bad.Count > 0) lines.Add(stopReason ?? T($"{bad.Count} PC(s): wrong user name or password: {Ips(bad)}"));
        if (otherFail.Count > 0) lines.Add(T($"{otherFail.Count} PC(s) failed for another reason: {Ips(otherFail)}"));
        if (noSign.Count > 0) lines.Add(T($"{noSign.Count} device(s) with a PC maker's network card answer, but 135 and 445 are closed and nothing says Windows (a firewall that blocks everything, or not a PC): {Ips(noSign)}"));
        if (silent.Count > 0) lines.Add(T($"{silent.Count} device(s) did not answer at all: they are only in Windows' ARP table (turned off?). Run Get models again while they are on: {Ips(silent)}"));
        foreach (var l in lines) _engine.Log("Windows summary: " + l);
        if (closed.Count + blocked.Count + noSign.Count > 0)
        {
            _engine.Log("Windows summary: to open a PC's firewall, run these two lines once on it, in Command Prompt as administrator:");
            foreach (var c in AllowRemoteCommands) _engine.Log("Windows summary:   " + c);
        }

        var advice = new List<string>();
        if (stopReason != null || bad.Count > 0) advice.Add(WindowsAdvice(WinFail.BadLogin, false));
        else if (denied.Count > 0) advice.Add(WindowsAdvice(WinFail.AccessDenied, false));
        if (closed.Count + blocked.Count + noSign.Count > 0) advice.Add(WindowsAdvice(WinFail.Blocked, false));
        Ui.Box(this, string.Join("\n", lines) + "\n\n" + string.Join("\n\n", advice) + T("\n\nThe result for each PC is in the Log tab."),
            AppInfo.Name + T(" – Windows models"), MessageBoxButtons.OK, ok == 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
    }

    private void OnClosing(object? sender, FormClosingEventArgs e)
    {
        _lifetime.Cancel();
        _scanCts?.Cancel();
        _watcher.Dispose();
        if (_tray != null) { _tray.Visible = false; _tray.Dispose(); }
        _uiTimer.Stop();
        _repeatTimer.Stop();
        _updateTimer.Stop();
        if (_reach.Added.Count > 0) _reach.RemoveAllBlocking();
        _engine.Dispose();
    }
}
