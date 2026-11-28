using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using NetFinder.Core.Model;

namespace NetFinder.Core.Net;

/// <summary>
/// Reads a printer's toner / ink levels (Printer-MIB, RFC 3805) and a switch's ports and learned MAC addresses
/// (IF-MIB, BRIDGE-MIB, Q-BRIDGE-MIB) over SNMP with the read community. Works on any brand that follows the standard MIBs.
/// </summary>
public static class SnmpTables
{
    private const int Timeout = 900;

    // Printer-MIB
    private const string Supplies = "1.3.6.1.2.1.43.11.1.1";         // prtMarkerSuppliesEntry
    private const string Colorants = "1.3.6.1.2.1.43.12.1.1.4";       // prtMarkerColorantValue ("black", "cyan"…)
    private const string LifeCount = "1.3.6.1.2.1.43.10.2.1.4";       // prtMarkerLifeCount (pages printed)
    private const string ConsoleText = "1.3.6.1.2.1.43.16.5.1.2";     // prtConsoleDisplayBufferText ("Ready", "Toner low")
    private const string AlertText = "1.3.6.1.2.1.43.18.1.1.8";       // prtAlertDescription
    private const string HrPrinterStatus = "1.3.6.1.2.1.25.3.5.1.1";
    private const string HrPrinterErrors = "1.3.6.1.2.1.25.3.5.1.2";

    // switches and routers
    public const string BaseNumPorts = "1.3.6.1.2.1.17.1.2.0";
    public const string IpForwarding = "1.3.6.1.2.1.4.1.0";
    private const string BasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2";
    private const string QFdbPort = "1.3.6.1.2.1.17.7.1.2.2.1.2";     // dot1qTpFdbPort (index: VLAN . MAC)
    private const string FdbPort = "1.3.6.1.2.1.17.4.3.1.2";          // dot1dTpFdbPort (index: MAC)
    private const string IfDescr = "1.3.6.1.2.1.2.2.1.2";
    private const string IfType = "1.3.6.1.2.1.2.2.1.3";
    private const string IfSpeed = "1.3.6.1.2.1.2.2.1.5";
    private const string IfAdmin = "1.3.6.1.2.1.2.2.1.7";
    private const string IfOper = "1.3.6.1.2.1.2.2.1.8";
    private const string IfName = "1.3.6.1.2.1.31.1.1.1.1";
    private const string IfHighSpeed = "1.3.6.1.2.1.31.1.1.1.15";
    private const string IfAlias = "1.3.6.1.2.1.31.1.1.1.18";
    private const string ArpTable = "1.3.6.1.2.1.4.22.1.2";           // ipNetToMediaPhysAddress (index: ifIndex . IP)
    private const string CiscoVlans = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"; // vtpVlanState (index: 1 . VLAN)

    // ───────────────────────────── printers ─────────────────────────────

    /// <summary>Toner / ink levels, pages and status. Null when the device has no Printer-MIB supplies and no printer status.</summary>
    public static async Task<PrinterState?> ReadPrinterAsync(IPAddress ip, string community, int version, CancellationToken ct)
    {
        var rows = await Snmp.WalkAsync(ip, community, Supplies, Timeout, ct, version, maxRows: 600);
        var status = await FirstAsync(ip, community, HrPrinterStatus, version, ct);
        if ((rows == null || rows.Count == 0) && status == null) return null;
        var colorants = (await Snmp.WalkAsync(ip, community, Colorants, Timeout, ct, version, maxRows: 40) ?? new())
            .Where(v => v.Text != null).ToDictionary(v => string.Join(".", Snmp.Index(v.Oid, Colorants)), v => v.Text!.Trim().ToLowerInvariant());
        var pages = (await FirstAsync(ip, community, LifeCount, version, ct))?.Number;
        var errors = await FirstAsync(ip, community, HrPrinterErrors, version, ct);
        var console = (await Snmp.WalkAsync(ip, community, ConsoleText, Timeout, ct, version, maxRows: 6) ?? new()).Select(v => v.Text?.Trim()).Where(t => !string.IsNullOrEmpty(t)).ToList();
        var alerts = (await Snmp.WalkAsync(ip, community, AlertText, Timeout, ct, version, maxRows: 12) ?? new()).Select(v => v.Text?.Trim()).Where(t => !string.IsNullOrEmpty(t)).ToList();
        return BuildPrinter(rows ?? new(), colorants, pages, status?.Number, errors?.Raw, console!, alerts!);
    }

    /// <summary>Turns the raw Printer-MIB rows into supplies (also used by the self-test).</summary>
    public static PrinterState BuildPrinter(IReadOnlyList<SnmpVar> supplyRows, IReadOnlyDictionary<string, string> colorants, long? pages, long? hrStatus,
        byte[]? errorBits, IReadOnlyList<string> console, IReadOnlyList<string> alertTexts)
    {
        // column → (index "1.3") → value
        var table = new Dictionary<int, Dictionary<string, SnmpVar>>();
        foreach (var v in supplyRows)
        {
            var idx = Snmp.Index(v.Oid, Supplies);
            if (idx.Length < 3) continue;
            if (!table.TryGetValue(idx[0], out var col)) table[idx[0]] = col = new();
            col[string.Join(".", idx[1..])] = v;
        }
        long? Num(int column, string row) => table.TryGetValue(column, out var c) && c.TryGetValue(row, out var v) ? v.Number : null;
        string? Str(int column, string row) => table.TryGetValue(column, out var c) && c.TryGetValue(row, out var v) ? v.Text : null;

        var rowsIdx = table.Values.SelectMany(c => c.Keys).Distinct().OrderBy(k => k, Comparer<string>.Create(Snmp.CompareOid)).ToList();
        var list = new List<(PrinterSupply S, int Order)>();
        foreach (var r in rowsIdx)
        {
            var type = (int)(Num(5, r) ?? 1);
            var cls = (int)(Num(4, r) ?? 1);
            var unit = (int)(Num(7, r) ?? 0);
            var max = Num(8, r) ?? -2;
            var level = Num(9, r);
            if (level == null && max == -2 && Str(6, r) == null) continue;
            var descr = Clean(Str(6, r));
            var hr = r.Split('.')[0];
            var color = Num(3, r) is > 0 and var ci && colorants.TryGetValue($"{hr}.{ci}", out var cv) && cv is not ("" or "unknown" or "other" or "none")
                ? cv : ColorFromText(descr);
            var fillsUp = cls == 4 || type is 4 or 8 or 14 or 24 or 26;
            var colorant = !fillsUp && type is 3 or 5 or 6 or 7 or 12 or 13 or 21 || !fillsUp && type is 1 or 2 && color != null;
            int? pct = null;
            if (level is >= 0 && max > 0) pct = (int)Math.Clamp(Math.Round(level.Value * 100.0 / max), 0, 100);
            else if (level is >= 0 and <= 100 && (unit == 19 || max is -1 or -2 or 100)) pct = (int)level.Value;
            var state = pct is { } p ? (fillsUp ? (p >= 100 ? "Full" : "OK") : p == 0 ? "Empty" : p <= 10 ? "Low" : "OK")
                : level == -3 ? "OK" : "Unknown";
            var name = SupplyName(type, color, descr, colorant);
            var detail = descr != null && !descr.Equals(name, StringComparison.OrdinalIgnoreCase) ? descr : null;
            var order = colorant ? ColorOrder(color) : 100 + list.Count;
            list.Add((new PrinterSupply(name, color, pct, state, fillsUp, colorant) { Detail = detail }, order));
        }
        var supplies = list.OrderBy(x => x.Order).ThenBy(x => list.IndexOf(x)).Select(x => x.S).ToList();

        var alerts = new List<string>();
        foreach (var e in ErrorNames(errorBits)) alerts.Add(e);
        foreach (var a in alertTexts) if (!alerts.Contains(a, StringComparer.OrdinalIgnoreCase)) alerts.Add(a);
        var statusText = console.FirstOrDefault(c => c.Any(char.IsLetter)) ?? hrStatus switch
        {
            3 => "Ready", 4 => "Printing", 5 => "Warming up", _ => null,
        };
        foreach (var c in console.Skip(1).Where(c => c.Any(char.IsLetter))) if (!alerts.Contains(c, StringComparer.OrdinalIgnoreCase)) alerts.Add(c);
        return new PrinterState(supplies, pages is > 0 ? pages : null, statusText, alerts.Take(6).ToList(), DateTime.Now);
    }

    private static readonly string[] ErrorBits =
    {
        "Paper low", "No paper", "Toner low", "No toner", "Door open", "Paper jam", "Offline", "Needs service",
        "Input tray missing", "Output tray missing", "Supply missing", "Output tray almost full", "Output tray full", "Input tray empty", "Maintenance due",
    };

    /// <summary>hrPrinterDetectedErrorState: bit 0 is the top bit of the first byte.</summary>
    internal static IEnumerable<string> ErrorNames(byte[]? bits)
    {
        if (bits == null) yield break;
        for (var i = 0; i < Math.Min(bits.Length * 8, ErrorBits.Length); i++)
            if ((bits[i / 8] & (0x80 >> (i % 8))) != 0) yield return ErrorBits[i];
    }

    private static readonly string[] KnownColors = { "black", "cyan", "magenta", "yellow" };

    private static int ColorOrder(string? c)
    {
        if (c == null) return 50;
        for (var i = 0; i < KnownColors.Length; i++) if (c.Contains(KnownColors[i])) return i * 10 + (c == KnownColors[i] ? 0 : 1);
        return 45;
    }

    /// <summary>"Black Toner Cartridge" → "black"; Kyocera "TK-5240K" → "black" (its last letter is the color).</summary>
    public static string? ColorFromText(string? t)
    {
        if (t == null) return null;
        var m = Regex.Match(t, @"\b(photo black|matte black|light cyan|light magenta|light black|black|cyan|magenta|yellow|gr[ae]y|red|blue|green)\b", RegexOptions.IgnoreCase);
        if (m.Success) return m.Value.ToLowerInvariant().Replace("grey", "gray");
        var k = Regex.Match(t, @"^(TK|TN|CLT|TT|T)-?\d{2,5}([KCMY])$", RegexOptions.IgnoreCase);
        return k.Success ? k.Groups[2].Value.ToUpperInvariant() switch { "K" => "black", "C" => "cyan", "M" => "magenta", _ => "yellow" } : null;
    }

    private static string SupplyName(int type, string? color, string? descr, bool colorant)
    {
        var kind = type switch
        {
            3 or 21 => "toner", 5 or 6 => "ink", 7 => "ribbon", 12 or 13 => "wax",
            4 => "Waste toner box", 8 => "Waste ink", 9 => "Drum", 10 => "Developer", 15 => "Fuser", 18 => "Cleaning unit", 20 => "Transfer unit",
            26 => "Waste paper", 32 => "Staples", _ => null,
        };
        if (colorant && color != null) return Cap(color) + " " + (kind is "toner" or "ink" or "ribbon" or "wax" ? kind : descr != null && Regex.IsMatch(descr, @"\bink\b", RegexOptions.IgnoreCase) ? "ink" : "toner");
        if (kind != null && char.IsUpper(kind[0])) return color != null && kind is "Drum" or "Developer" ? $"{kind} ({color})" : kind;
        if (descr != null) return descr.Length > 40 ? descr[..40] + "…" : Cap(descr);
        return kind != null ? Cap(kind) : "Supply";
    }

    private static string Cap(string s) => s.Length == 0 ? s : char.ToUpper(s[0], CultureInfo.InvariantCulture) + s[1..];

    private static string? Clean(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = Regex.Replace(s.Replace('\0', ' '), @"\s+", " ").Trim();
        // a value the client turned into hex (not text) is no description
        return s.Length == 0 || Regex.IsMatch(s, "^[0-9A-F]{8,}$") ? null : s;
    }

    private static async Task<SnmpVar?> FirstAsync(IPAddress ip, string community, string column, int version, CancellationToken ct) =>
        (await Snmp.WalkAsync(ip, community, column, Timeout, ct, version, maxRows: 1))?.FirstOrDefault();

    // ───────────────────────────── switches and routers ─────────────────────────────

    /// <summary>
    /// Ports + learned MACs of a switch, and the ARP table of a router / layer-3 switch.
    /// Null when the device is neither (no BRIDGE-MIB ports and not forwarding IP).
    /// </summary>
    public static async Task<SwitchState?> ReadSwitchAsync(IPAddress ip, string community, int version, string? maker, CancellationToken ct)
    {
        long numPorts = 0, forwarding = 0;
        foreach (var o in new[] { BaseNumPorts, IpForwarding })
        {
            // one at a time: in SNMP v1 a missing OID fails the whole request
            var r = await Snmp.GetAsync(ip, community, new[] { o }, Timeout, ct, version);
            if (r == null) return null;
            if (r.TryGetValue(o, out var t) && long.TryParse(t, out var n)) { if (o == BaseNumPorts) numPorts = n; else forwarding = n; }
        }
        var bridge = numPorts > 0;
        var router = forwarding == 1;
        if (!bridge && !router) return null;

        var arp = new Dictionary<string, string>();
        if (router)
            foreach (var v in await Snmp.WalkAsync(ip, community, ArpTable, Timeout, ct, version, maxRows: 8000) ?? new())
            {
                var idx = Snmp.Index(v.Oid, ArpTable);
                if (idx.Length != 5 || v.Mac is not { } mac || !Mac.IsUnicast(mac)) continue;
                arp[$"{idx[1]}.{idx[2]}.{idx[3]}.{idx[4]}"] = mac;
            }
        if (!bridge) return new SwitchState(Array.Empty<SwitchPort>(), arp, false, DateTime.Now);

        // MAC → (bridge port, VLAN), and bridge port → ifIndex
        var learned = new List<(string Mac, int Port, int Vlan, string Context)>();
        var bpIf = new Dictionary<(string, int), int>();
        async Task ReadBridge(string com, string context)
        {
            foreach (var v in await Snmp.WalkAsync(ip, com, BasePortIfIndex, Timeout, ct, version, maxRows: 2000) ?? new())
                if (Snmp.Index(v.Oid, BasePortIfIndex) is [var bp] && v.Number is { } ifx) bpIf[(context, bp)] = (int)ifx;
            var q = await Snmp.WalkAsync(ip, com, QFdbPort, Timeout, ct, version, maxRows: 20_000) ?? new();
            foreach (var v in q)
                if (Snmp.Index(v.Oid, QFdbPort) is { Length: 7 } i && v.Number is > 0 and var port)
                    learned.Add((MacOf(i[1..]), (int)port, i[0], context));
            if (q.Count > 0) return;
            foreach (var v in await Snmp.WalkAsync(ip, com, FdbPort, Timeout, ct, version, maxRows: 20_000) ?? new())
                if (Snmp.Index(v.Oid, FdbPort) is { Length: 6 } i && v.Number is > 0 and var port)
                    learned.Add((MacOf(i), (int)port, context.Length > 0 ? int.Parse(context) : 0, context));
        }
        await ReadBridge(community, "");
        // Cisco keeps one bridge table per VLAN, read with "community@VLAN"
        if (maker == "Cisco")
        {
            var vlans = (await Snmp.WalkAsync(ip, community, CiscoVlans, Timeout, ct, version, maxRows: 200) ?? new())
                .Select(v => Snmp.Index(v.Oid, CiscoVlans)).Where(i => i.Length == 2 && i[1] is > 1 and < 1002 or > 1005 and < 4095).Select(i => i[1]).Distinct().Take(64).ToList();
            foreach (var vlan in vlans) await ReadBridge($"{community}@{vlan}", vlan.ToString(CultureInfo.InvariantCulture));
        }

        // interfaces
        async Task<Dictionary<int, SnmpVar>> Column(string col) =>
            (await Snmp.WalkAsync(ip, community, col, Timeout, ct, version, maxRows: 3000) ?? new())
            .Where(v => Snmp.Index(v.Oid, col).Length == 1).GroupBy(v => Snmp.Index(v.Oid, col)[0]).ToDictionary(g => g.Key, g => g.First());
        var names = await Column(IfName);
        var descrs = await Column(IfDescr);
        var types = await Column(IfType);
        var oper = await Column(IfOper);
        var admin = await Column(IfAdmin);
        var alias = await Column(IfAlias);
        var speed = await Column(IfHighSpeed);
        var speedBps = speed.Count == 0 ? await Column(IfSpeed) : new();

        int IfOf(string context, int bp) => bpIf.TryGetValue((context, bp), out var x) ? x : bpIf.TryGetValue(("", bp), out var y) ? y : bp;
        var macsByIf = learned.GroupBy(l => IfOf(l.Context, l.Port)).ToDictionary(g => g.Key, g => g.ToList());
        var portIfs = bpIf.Values.ToHashSet();
        foreach (var (ifx, t) in types) if (t.Number is 6 or 62 or 69 or 117) portIfs.Add(ifx);
        foreach (var ifx in macsByIf.Keys) portIfs.Add(ifx);

        var ports = new List<SwitchPort>();
        foreach (var ifx in portIfs.OrderBy(x => x))
        {
            if (types.TryGetValue(ifx, out var tp) && tp.Number is 24 or 1 or 53 && !macsByIf.ContainsKey(ifx)) continue; // loopback, other, virtual
            var name = PortName(names.GetValueOrDefault(ifx)?.Text, descrs.GetValueOrDefault(ifx)?.Text, ifx);
            var mbps = speed.GetValueOrDefault(ifx)?.Number ?? (speedBps.GetValueOrDefault(ifx)?.Number is { } bps ? bps / 1_000_000 : 0);
            var macs = macsByIf.TryGetValue(ifx, out var l) ? l : new();
            ports.Add(new SwitchPort(ifx, name, Clean(alias.GetValueOrDefault(ifx)?.Text), oper.GetValueOrDefault(ifx)?.Number == 1, admin.GetValueOrDefault(ifx)?.Number == 2,
                mbps, macs.Select(m => m.Mac).Distinct().OrderBy(m => m).ToList(), macs.Select(m => m.Vlan).Where(v => v > 0).Distinct().OrderBy(v => v).ToList()));
        }
        return new SwitchState(ports, arp, true, DateTime.Now);
    }

    private static string MacOf(int[] a) => string.Join(":", a.Take(6).Select(b => ((byte)b).ToString("X2")));

    /// <summary>ifName, else a short ifDescr: "gigabitEthernet 1/0/5 : copper" → "gigabitEthernet 1/0/5", "D-Link DES-1210 … Port 5" → "Port 5".</summary>
    public static string PortName(string? ifName, string? ifDescr, int ifIndex)
    {
        var n = Clean(ifName);
        if (n != null) return n;
        var d = Clean(ifDescr);
        if (d == null) return ifIndex.ToString(CultureInfo.InvariantCulture);
        d = Regex.Replace(d, @"\s*:\s*(copper|fiber|fibre)\s*$", "", RegexOptions.IgnoreCase);
        var m = Regex.Match(d, @"\bport\s*#?\s*(\d+(/\d+)*)\s*$", RegexOptions.IgnoreCase);
        return d.Length > 24 && m.Success ? "Port " + m.Groups[1].Value : d;
    }
}
