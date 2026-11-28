using System.Net;
using System.Text;
using NetFinder.Core;
using NetFinder.Core.Model;
using NetFinder.Core.Nvr;
using static NetFinder.Core.Text.L;

namespace NetFinder.Ui;

/// <summary>
/// "Show cameras": log in to an NVR/DVR and list the cameras recorded by it (channel, name, IP, model, status).
/// The cameras are also added to the main list. The password lives only in this window and is never saved.
/// </summary>
internal sealed class NvrForm : Form
{
    private readonly NetworkEngine _engine;
    private readonly Device _nvr;
    private readonly Action<Device> _openDevice;
    private readonly Action<string> _openUrl;

    private readonly TextBox _address = new() { Width = 260 };
    private readonly ComboBox _brand = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 260 };
    private readonly TextBox _user = new() { Width = 160, Text = "admin" };
    private readonly TextBox _pass = new() { Width = 160, UseSystemPasswordChar = true };
    private readonly Button _connect = new() { Text = T("Show cameras"), AutoSize = true, Font = Theme.Bold, BackColor = Theme.Accent, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Padding = new Padding(10, 3, 10, 3) };
    private readonly Label _status = new() { AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(0, 6, 0, 6), MaximumSize = new Size(900, 0) };
    private readonly DataGridView _grid = new();
    private readonly Button _copy = new() { Text = T("Copy list"), AutoSize = true, Enabled = false };
    private readonly Button _openCam = new() { Text = T("Open camera"), AutoSize = true, Enabled = false };
    private readonly Button _openNvr = new() { Text = T("Open NVR web page"), AutoSize = true };
    private NvrResult? _result;
    private CancellationTokenSource? _cts;

    public NvrForm(NetworkEngine engine, Device nvr, Action<Device> openDevice, Action<string> openUrl)
    {
        _engine = engine;
        _nvr = nvr;
        _openDevice = openDevice;
        _openUrl = openUrl;
        string ip, title;
        SortedSet<int> ports;
        lock (nvr) { ip = nvr.Ip?.ToString() ?? ""; title = nvr.DisplayName; ports = new SortedSet<int>(nvr.OpenPorts); }

        Text = T($"Cameras on NVR {ip}") + (title.Length > 0 ? "  " + Bidi($"({title})") : "");
        Font = Theme.Base;
        Ui.Direction(this);
        Ui.Ltr(_address, _user, _pass);
        Ui.LtrCells(_grid);
        Icon = Theme.AppIcon();
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(1080, 620);
        MinimumSize = new Size(760, 440);
        BackColor = Color.White;
        ShowInTaskbar = false;

        _address.Text = DefaultAddress(ip, ports);
        _brand.Items.AddRange(new object[] { T("Automatic"), "Hikvision  (HiLook, Annke, LTS…)", "Dahua  (Amcrest, Imou, Lorex, CP Plus…)" });
        _brand.SelectedIndex = 0;
        _connect.FlatAppearance.BorderSize = 0;
        _connect.Click += async (_, _) => await ConnectAsync();
        _pass.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await ConnectAsync(); } };

        // login box
        var login = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 5, Padding = new Padding(14, 12, 14, 0) };
        Label L(string t) => new() { Text = t, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 8, 6, 0) };
        login.Controls.Add(L(T("NVR address:")), 0, 0);
        login.Controls.Add(_address, 1, 0);
        login.Controls.Add(L(T("Brand:")), 2, 0);
        login.Controls.Add(_brand, 3, 0);
        login.Controls.Add(L(T("User:")), 0, 1);
        login.Controls.Add(_user, 1, 1);
        login.Controls.Add(L(T("Password:")), 2, 1);
        var passRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        passRow.Controls.Add(_pass);
        _connect.Margin = new Padding(10, 0, 0, 0);
        passRow.Controls.Add(_connect);
        login.Controls.Add(passRow, 3, 1);
        var note = new Label
        {
            Text = T("The user and password of the NVR (the ones you use on its web page). The password is not saved. " +
                   "Careful: after a few wrong passwords the NVR locks this user for a while (often 30 minutes)."),
            AutoSize = true, MaximumSize = new Size(1000, 0), ForeColor = Theme.Muted, Font = Theme.Small, Margin = new Padding(0, 8, 0, 0),
        };
        login.Controls.Add(note, 0, 2);
        login.SetColumnSpan(note, 5);
        login.Controls.Add(_status, 0, 3);
        login.SetColumnSpan(_status, 5);

        BuildGrid();

        var bottom = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(10, 6, 10, 8), FlowDirection = FlowDirection.LeftToRight };
        var close = new Button { Text = T("Close"), AutoSize = true, DialogResult = DialogResult.Cancel };
        _copy.Click += (_, _) => CopyList();
        _openCam.Click += (_, _) => OpenSelected();
        _openNvr.Click += (_, _) => _openUrl(_address.Text.Trim());
        bottom.Controls.AddRange(new Control[] { _openCam, _openNvr, _copy, close });
        CancelButton = close;

        var gridHost = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 4, 14, 0) };
        gridHost.Controls.Add(_grid);
        Controls.Add(gridHost);
        Controls.Add(bottom);
        Controls.Add(login);

        Shown += (_, _) => _pass.Focus();
        FormClosing += (_, _) => { _cts?.Cancel(); _pass.Text = ""; };
    }

    /// <summary>http on 80, else https on 443, else the first web-like open port, else http.</summary>
    private static string DefaultAddress(string ip, SortedSet<int> ports)
    {
        if (ports.Contains(80) || ports.Count == 0) return $"http://{ip}";
        if (ports.Contains(443)) return $"https://{ip}";
        foreach (var p in ports)
            if (Core.Actions.BuiltInActions.HttpsPorts.Contains(p)) return $"https://{ip}:{p}";
        foreach (var p in ports)
            if (Core.Actions.BuiltInActions.HttpPorts.Contains(p) && p != 37777) return $"http://{ip}:{p}";
        return $"http://{ip}";
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
        _grid.BorderStyle = BorderStyle.FixedSingle;
        _grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        _grid.GridColor = Color.FromArgb(235, 235, 235);
        _grid.EnableHeadersVisualStyles = false;
        _grid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Panel;
        _grid.ColumnHeadersDefaultCellStyle.Font = Theme.Bold;
        _grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
        _grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(204, 228, 247);
        _grid.DefaultCellStyle.SelectionForeColor = Color.Black;
        _grid.RowTemplate.Height = 26;
        void Col(string name, string header, int width, bool fill = false)
        {
            var c = new DataGridViewTextBoxColumn { Name = name, HeaderText = header, Width = width };
            if (fill) { c.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill; c.MinimumWidth = 120; }
            _grid.Columns.Add(c);
        }
        Col("Ch", T("Ch"), 44);
        Col("Name", T("Camera name"), 170, fill: true);
        Col("Ip", T("IP address"), 120);
        Col("Port", T("Port"), 60);
        Col("Model", T("Model"), 170);
        Col("Serial", T("Serial number"), 170);
        Col("Mac", T("MAC"), 125);
        Col("Status", T("Status"), 120);
        Col("Net", T("Open from this PC"), 160);
        _grid.SelectionChanged += (_, _) => _openCam.Enabled = SelectedCamera()?.Ip != null;
        _grid.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0) OpenSelected(); };
    }

    private async Task ConnectAsync()
    {
        if (_cts != null) return;
        if (!Uri.TryCreate(_address.Text.Trim().Contains("://") ? _address.Text.Trim() : "http://" + _address.Text.Trim(), UriKind.Absolute, out var uri) ||
            (uri.Scheme != "http" && uri.Scheme != "https"))
        {
            SetStatus(T("Type the NVR address like http://192.168.1.64 or https://192.168.1.64:8443"), error: true);
            return;
        }
        if (_user.Text.Trim().Length == 0) { SetStatus(T("Type the NVR user name (usually admin)."), error: true); return; }

        var brand = _brand.SelectedIndex switch { 1 => NvrBrand.Hikvision, 2 => NvrBrand.Dahua, _ => NvrBrand.Auto };
        _cts = new CancellationTokenSource();
        _connect.Enabled = false;
        UseWaitCursor = true;
        SetStatus(T($"Logging in to {uri.Authority}…"), error: false);
        try
        {
            var user = _user.Text.Trim();
            var pass = _pass.Text;
            _result = await Task.Run(() => NvrClient.ReadAsync(uri, user, pass, brand, _cts.Token));
            var added = NvrClient.AddToStore(_engine.Store, _nvr, _result);
            Fill(_result);
            var online = _result.Cameras.Count(c => c.Online == true);
            var sb = new StringBuilder();
            sb.Append(T($"{_result.BrandName} {_result.Model} – {_result.Cameras.Count} camera(s)"));
            if (_result.Cameras.Any(c => c.Online != null)) sb.Append(T($", {online} online"));
            sb.Append('.');
            if (added > 0) sb.Append(T($"  {added} added to the main list."));
            if (_result.Cameras.Any(c => c.Ip != null && !IsReachable(c.Ip)))
                sb.Append(T("  Cameras marked \"through the NVR\" are on the NVR's own camera network (e.g. its PoE ports): open them from the NVR's web page."));
            foreach (var n in _result.Notes) sb.Append("  " + n);
            SetStatus(sb.ToString(), error: false);
            _engine.Log($"NVR {uri.Authority}: {_result.BrandName} {_result.Model}, {_result.Cameras.Count} cameras");
        }
        catch (NvrException ex)
        {
            SetStatus(ex.Message.Replace("\n\n", "  "), error: true);
            _engine.Log($"NVR {uri.Authority}: {ex.Message.Split('\n')[0]}");
            if (ex.WrongPassword) { _pass.SelectAll(); _pass.Focus(); }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            SetStatus(T("Could not read the cameras: ") + ex.Message, error: true);
            _engine.Log($"NVR {uri.Authority} failed: {ex}");
        }
        finally
        {
            _cts?.Dispose(); _cts = null;
            if (!IsDisposed) { _connect.Enabled = true; UseWaitCursor = false; }
        }
    }

    private bool IsReachable(string ip)
    {
        if (!IPAddress.TryParse(ip, out var a) || _engine.Store.FindByIp(a) is not { } d) return false;
        lock (d) return d.Reachable;
    }

    private void Fill(NvrResult r)
    {
        _grid.Rows.Clear();
        foreach (var c in r.Cameras)
        {
            var net = c.Ip == null ? T("Analog (no IP)") : IsReachable(c.Ip) ? T("Directly") : T("Through the NVR");
            var i = _grid.Rows.Add(c.Channel, c.Name, c.Ip ?? "—", c.Port?.ToString() ?? "", c.Model ?? "", c.Serial ?? "", c.Mac ?? "", c.Status, net);
            var row = _grid.Rows[i];
            row.Tag = c;
            row.Cells["Status"].Style.ForeColor = c.Online switch { true => Theme.Good, false => Color.FromArgb(196, 43, 28), _ => Color.Black };
            if (net == "Through the NVR") row.Cells["Net"].Style.ForeColor = Theme.OtherSubnetText;
        }
        _copy.Enabled = r.Cameras.Count > 0;
    }

    private NvrCamera? SelectedCamera() => _grid.SelectedRows.Count > 0 ? _grid.SelectedRows[0].Tag as NvrCamera : null;

    private void OpenSelected()
    {
        var c = SelectedCamera();
        if (c?.Ip == null || !IPAddress.TryParse(c.Ip, out var ip)) return;
        if (_engine.Store.FindByIp(ip) is { } d) _openDevice(d);
        else _openUrl($"http://{c.Ip}");
    }

    private void SetStatus(string text, bool error)
    {
        _status.Text = text;
        _status.ForeColor = error ? Color.FromArgb(196, 43, 28) : Theme.Good;
    }

    private void CopyList()
    {
        if (_result == null) return;
        var sb = new StringBuilder();
        sb.AppendLine($"NVR {_address.Text.Trim()}\t{_result.BrandName} {_result.Model}\t{_result.Serial}");
        sb.AppendLine(T("Ch\tName\tIP\tPort\tModel\tSerial\tMAC\tStatus"));
        foreach (var c in _result.Cameras)
            sb.AppendLine(string.Join("\t", c.Channel, c.Name, c.Ip, c.Port, c.Model, c.Serial, c.Mac, c.Status));
        Clipboard.SetText(sb.ToString());
        SetStatus(T("List copied. Paste it in Excel or a message."), error: false);
    }
}
