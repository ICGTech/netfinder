using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using NetFinder.Core.Model;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Actions;

// Enrichers that read a device's MODEL without any password. They run after the ports of a device are
// checked (automatically for devices this PC can reach, or with "Get models" for the whole network).

/// <summary>SNMP with the read community ("public"): sysDescr / sysName, ENTITY-MIB model + serial, Printer-MIB name.</summary>
public sealed class SnmpEnricher : IDeviceEnricher
{
    public string Name => "SNMP";
    private const int Timeout = 700;

    public async Task EnrichAsync(Device device, EnrichContext ctx, CancellationToken ct)
    {
        IPAddress? ip;
        lock (device) ip = device.Ip;
        if (ip == null) return;
        var sysOids = new[] { Snmp.SysDescr, Snmp.SysObjectId, Snmp.SysName, Snmp.SysLocation };
        foreach (var community in ctx.Settings.SnmpCommunityList)
        {
            // v2c and v1 at the same time (old printers speak only v1); a wrong community gets no answer at all
            var v2 = Snmp.GetAsync(ip, community, sysOids, Timeout, ct, version: 1);
            var v1 = Snmp.GetAsync(ip, community, sysOids, Timeout, ct, version: 0);
            await Task.WhenAll(v2, v1);
            var sys = (v2.Result is { Count: > 0 } ? v2.Result : null) ?? (v1.Result is { Count: > 0 } ? v1.Result : null);
            if (sys == null) continue;
            var version = v2.Result is { Count: > 0 } ? 1 : 0;

            var descr = sys.GetValueOrDefault(Snmp.SysDescr);
            var objId = sys.GetValueOrDefault(Snmp.SysObjectId);
            var name = sys.GetValueOrDefault(Snmp.SysName);
            var location = sys.GetValueOrDefault(Snmp.SysLocation);
            var maker = Enterprise(objId);

            (string Oid, string Value)? entModel = null, entSerial = null;
            Dictionary<string, string>? printer = null;
            if (version == 1)
            {
                entModel = await Snmp.FirstInColumnAsync(ip, community, Snmp.EntModelName, Timeout, ct);
                if (entModel != null) entSerial = await Snmp.FirstInColumnAsync(ip, community, Snmp.EntSerialNum, Timeout, ct);
                printer = await Snmp.GetAsync(ip, community, new[] { Snmp.PrinterName, Snmp.PrinterSerial, Snmp.HrDeviceDescr1 }, Timeout, ct, version: 1);
            }
            else
            {
                // v1: a missing OID fails the whole request, so ask one at a time
                printer = new Dictionary<string, string>();
                foreach (var o in new[] { Snmp.PrinterName, Snmp.PrinterSerial })
                    if (await Snmp.GetAsync(ip, community, new[] { o }, Timeout, ct, version: 0) is { } r) foreach (var kv in r) printer[kv.Key] = kv.Value;
            }
            var isPrinter = printer != null && printer.ContainsKey(Snmp.PrinterName) || printer?.ContainsKey(Snmp.PrinterSerial) == true;
            var printerModel = printer?.GetValueOrDefault(Snmp.PrinterName) is { Length: > 0 } pn && !pn.Equals(name, StringComparison.OrdinalIgnoreCase)
                ? pn : isPrinter ? printer!.GetValueOrDefault(Snmp.HrDeviceDescr1) : null;

            ctx.Engine.Store.Touch(device, d =>
            {
                d.Sources.Add("SNMP");
                if (descr != null) d.Info["SNMP description"] = descr.Length > 200 ? descr[..200] + "…" : descr;
                if (name != null) { d.Info["SNMP name"] = name; d.Hostname ??= name; }
                if (location != null && !location.Equals("Unknown", StringComparison.OrdinalIgnoreCase) && !location.StartsWith("Sitting on the Dock")) d.Info["SNMP location"] = location;
                if (objId != null) d.Info["SNMP object ID"] = objId;
                if (maker != null) { d.Info["Maker (SNMP)"] = maker; d.Vendor ??= maker; }
                if (community != "public") d.Info["SNMP community"] = community;
                d.OfferModel(ModelFromDescr(descr), "SNMP description", 35);
                if (entModel != null) d.OfferModel(entModel.Value.Value, "SNMP", 80);
                if (entSerial != null) d.Info["Serial number"] = entSerial.Value.Value;
                if (printerModel != null) d.OfferModel(printerModel, "SNMP printer", 80);
                if (printer?.GetValueOrDefault(Snmp.PrinterSerial) is { Length: > 0 } ps) d.Info["Serial number"] = ps;
            });
            return;
        }
    }

    /// <summary>Model from sysDescr when it is short and looks like one ("TL-SG3428", "RouterOS CCR1009-7G-1C-1S+").</summary>
    internal static string? ModelFromDescr(string? descr)
    {
        if (string.IsNullOrWhiteSpace(descr)) return null;
        var line = descr.Split('\n')[0].Trim();
        var ros = Regex.Match(line, @"^RouterOS\s+(\S+)", RegexOptions.IgnoreCase);
        if (ros.Success) return "MikroTik " + ros.Groups[1].Value;
        if (Regex.IsMatch(line, @"^(Linux|Hardware:|Windows|Darwin|FreeBSD|SunOS|Microsoft)|Software[:,]|Version \d", RegexOptions.IgnoreCase)) return null;
        var first = line.Split(',')[0].Trim();
        return first.Length is > 2 and <= 40 && first.Any(char.IsDigit) && first.Any(char.IsLetter) ? first : null;
    }

    /// <summary>Maker from the enterprise number in sysObjectID (1.3.6.1.4.1.N…).</summary>
    internal static string? Enterprise(string? objId)
    {
        var m = objId == null ? null : Regex.Match(objId, @"^1\.3\.6\.1\.4\.1\.(\d+)");
        if (m is not { Success: true }) return null;
        return int.Parse(m.Groups[1].Value) switch
        {
            9 => "Cisco", 11 => "HP", 43 => "3Com", 171 => "D-Link", 207 => "Allied Telesis", 232 => "HP (Compaq)", 253 => "Xerox", 311 => "Microsoft",
            318 => "APC", 367 => "Ricoh", 534 => "Eaton", 641 => "Lexmark", 674 => "Dell", 890 => "Zyxel", 1248 => "Epson", 1347 => "Kyocera",
            1588 => "Brocade", 1602 => "Canon", 1916 => "Extreme Networks", 2011 => "Huawei", 2435 => "Brother", 2636 => "Juniper", 3375 => "F5",
            3902 => "ZTE", 3955 => "Linksys", 4413 => "Broadcom", 4526 => "Netgear", 6486 => "Alcatel-Lucent", 6574 => "Synology", 6876 => "VMware",
            8072 => "Linux (net-snmp)", 8741 => "SonicWall", 11863 => "TP-Link", 12356 => "Fortinet", 14823 => "Aruba", 14988 => "MikroTik",
            17713 => "Cambium", 18334 => "Konica Minolta", 24681 => "QNAP", 25053 => "Ruckus", 25461 => "Palo Alto", 25506 => "H3C",
            30065 => "Arista", 39165 => "Hikvision", 41112 => "Ubiquiti", 1004849 => "Dahua", 4881 => "Ruijie", 37072 => "Tenda", 2620 => "Check Point",
            _ => null,
        };
    }
}

/// <summary>UPnP device description (routers, TVs, NAS, printers, cameras): friendly name, maker, model, serial.</summary>
public sealed class UpnpEnricher : IDeviceEnricher
{
    public string Name => "UPnP";

    public async Task EnrichAsync(Device device, EnrichContext ctx, CancellationToken ct)
    {
        IPAddress? ip; string? loc; bool worthAsking;
        lock (device)
        {
            ip = device.Ip;
            loc = device.Info.GetValueOrDefault("UPnP description URL");
            worthAsking = device.Info.ContainsKey("UPnP server") || device.OpenPorts.Any(p => p is 80 or 443 or 1900 or 2869 or 5000 or 49152 or 8008 or 8080) ||
                          device.EffectiveType is DeviceTypes.Router or DeviceTypes.Tv or DeviceTypes.Nas or DeviceTypes.Printer or DeviceTypes.Camera
                              or DeviceTypes.Nvr or DeviceTypes.AccessPoint or DeviceTypes.Iot or DeviceTypes.Console;
        }
        if (ip == null) return;
        if (loc == null && worthAsking) loc = (await Upnp.SearchAsync(ip, 1200, ct)).FirstOrDefault();
        if (loc == null || !Uri.TryCreate(loc, UriKind.Absolute, out var uri) || uri.Host != ip.ToString()) return;
        var desc = await Upnp.GetDescriptionAsync(loc, ct);
        if (desc == null) return;
        ctx.Engine.Store.Touch(device, d =>
        {
            d.Info["UPnP description URL"] = loc;
            // on a Windows PC the UPnP answer comes from some program on it (media sharing, a vendor agent…): it names the program, not the PC
            var pc = d.OpenPorts.Contains(135) || d.OpenPorts.Contains(3389) || d.Info.ContainsKey("Windows");
            if (pc)
            {
                if (desc.FriendlyName != null) d.Info["UPnP name"] = desc.FriendlyName;
                if (desc.Model != null) d.Info["UPnP model"] = desc.Model;
                return;
            }
            if (desc.FriendlyName != null) { d.Info["UPnP name"] = desc.FriendlyName; d.Hostname ??= desc.FriendlyName; }
            if (desc.Manufacturer != null) { d.Info["Manufacturer"] = desc.Manufacturer; d.Vendor ??= desc.Manufacturer; }
            if (desc.ModelDescription != null) d.Info["UPnP model description"] = desc.ModelDescription;
            if (desc.DeviceType != null) d.Info["UPnP device type"] = desc.DeviceType;
            if (desc.SerialNumber != null && desc.SerialNumber.Length > 3) d.Info.TryAdd("Serial number", desc.SerialNumber);
            d.OfferModel(desc.Model, "UPnP", 75);
        });
    }
}

/// <summary>ONVIF cameras / NVRs answer a WS-Discovery probe with their hardware model, no password needed.</summary>
public sealed class OnvifEnricher : IDeviceEnricher
{
    public string Name => "ONVIF";

    public async Task EnrichAsync(Device device, EnrichContext ctx, CancellationToken ct)
    {
        IPAddress? ip; bool worth;
        lock (device)
        {
            ip = device.Ip;
            worth = device.EffectiveType is DeviceTypes.Camera or DeviceTypes.Nvr || device.OpenPorts.Any(p => p is 554 or 8000 or 37777 or 8899) ||
                    (device.EffectiveType == DeviceTypes.Unknown && device.OpenPorts.Contains(80)) ||
                    device.Sources.Contains("ONVIF") || Regex.IsMatch(device.Vendor ?? "", "hikvision|dahua|uniview|axis|hanwha|vivotek|tiandy|milesight|reolink", RegexOptions.IgnoreCase);
        }
        if (ip == null || !worth) return;
        var info = await WsDiscovery.ProbeAsync(ip, 1500, ct);
        if (info != null) Apply(ctx.Engine.Store, device, info);
    }

    public static void Apply(DeviceStore store, Device device, OnvifInfo info) => store.Touch(device, d => ApplyTo(d, info));

    public static void ApplyTo(Device d, OnvifInfo info)
    {
        d.Sources.Add("ONVIF");
        if (info.Types.Length > 0) d.Info["ONVIF types"] = info.Types;
        if (info.Name != null)
        {
            d.Info["ONVIF name"] = info.Name;
            var brand = info.Name.Split(' ')[0];
            if (brand.Length > 2 && !brand.Any(char.IsDigit)) d.Vendor ??= brand;
        }
        if (info.Location != null) d.Info["ONVIF location"] = info.Location;
        if (info.XAddrs.Length > 0) d.Info["ONVIF address"] = info.XAddrs.Split(' ')[0];
        d.OfferModel(info.Hardware, "ONVIF", 75);
    }
}

/// <summary>Printers: IPP Get-Printer-Attributes on port 631 gives the exact make and model (prints nothing).</summary>
public sealed class IppEnricher : IDeviceEnricher
{
    public string Name => "IPP";

    public async Task EnrichAsync(Device device, EnrichContext ctx, CancellationToken ct)
    {
        IPAddress? ip;
        lock (device) ip = device.OpenPorts.Contains(631) ? device.Ip : null;
        if (ip == null) return;
        var a = await Ipp.GetPrinterAttributesAsync(ip, ct);
        if (a == null) return;
        var (mfg, mdl) = Ipp.ParseDeviceId(a.GetValueOrDefault("printer-device-id"));
        var model = a.GetValueOrDefault("printer-make-and-model") is { Length: > 0 } mm ? mm : mfg != null && mdl != null ? $"{mfg} {mdl}" : mdl;
        ctx.Engine.Store.Touch(device, d =>
        {
            d.Sources.Add("IPP");
            if (mfg != null) { d.Info["Manufacturer"] = mfg; d.Vendor ??= mfg; }
            if (a.GetValueOrDefault("printer-name") is { Length: > 0 } n) d.Info["Printer name"] = n;
            if (a.GetValueOrDefault("printer-info") is { Length: > 0 } i) d.Info["Printer info"] = i;
            if (a.GetValueOrDefault("printer-location") is { Length: > 0 } l) d.Info["Printer location"] = l;
            if (a.GetValueOrDefault("printer-firmware-string-version") is { Length: > 0 } fw) d.Info["Firmware"] = fw;
            d.OfferModel(model, "IPP", 85);
        });
    }
}

/// <summary>Greeting lines of FTP / SSH / Telnet: often name the product ("220 Brother HL-L2350DW", "SSH-2.0-ROSSSH").</summary>
public sealed class BannerEnricher : IDeviceEnricher
{
    public string Name => "Banners";

    public async Task EnrichAsync(Device device, EnrichContext ctx, CancellationToken ct)
    {
        IPAddress? ip; int[] ports;
        lock (device) { ip = device.Ip; ports = device.OpenPorts.Where(p => p is 21 or 22 or 23).ToArray(); }
        if (ip == null || ports.Length == 0) return;
        var banners = await Task.WhenAll(ports.Select(async p => (Port: p, Text: await ReadBannerAsync(ip, p, ct))));
        ctx.Engine.Store.Touch(device, d =>
        {
            foreach (var (p, text) in banners)
                if (!string.IsNullOrWhiteSpace(text)) d.Info[p switch { 21 => "FTP banner", 22 => "SSH banner", _ => "Telnet banner" }] = text;
        });
    }

    internal static async Task<string?> ReadBannerAsync(IPAddress ip, int port, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(2500);
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(ip, port, cts.Token);
            var s = tcp.GetStream();
            var buf = new byte[1024];
            var n = 0;
            try
            {
                while (n < buf.Length)
                {
                    var r = await s.ReadAsync(buf.AsMemory(n), cts.Token);
                    if (r <= 0) break;
                    n += r;
                    if (Array.IndexOf(buf, (byte)'\n', 0, n) >= 0 && port != 23) break;
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            return Clean(buf.AsSpan(0, n));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    /// <summary>Drops Telnet negotiation (IAC …) and control characters; keeps the first meaningful line.</summary>
    internal static string? Clean(ReadOnlySpan<byte> b)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < b.Length; i++)
        {
            if (b[i] == 0xFF && i + 1 < b.Length)
            {
                var cmd = b[i + 1];
                if (cmd == 0xFA) { while (i < b.Length && !(b[i] == 0xFF && i + 1 < b.Length && b[i + 1] == 0xF0)) i++; i++; } // sub-negotiation
                else if (cmd >= 0xFB) i += 2; // WILL/WONT/DO/DONT option
                else i++;
                continue;
            }
            var c = (char)b[i];
            sb.Append(c is '\r' or '\n' ? '\n' : c < 0x20 || c > 0x7E ? ' ' : c);
        }
        var line = sb.ToString().Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 2);
        if (line == null) return null;
        return line.Length > 120 ? line[..120] : line;
    }
}
