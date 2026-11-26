// Console harness used to test the engine on Linux/Windows without the GUI.
// usage: NetFinder.Probe <interface> [listenSeconds] [scan] [ports]
using NetFinder.Core;
using NetFinder.Core.Model;

// NVR mode: NetFinder.Probe nvr <url> <user> <pass> [hik|dahua]
if (args.Length >= 4 && args[0] == "nvr")
{
    var brand = args.Length > 4 ? (args[4] == "dahua" ? NetFinder.Core.Nvr.NvrBrand.Dahua : NetFinder.Core.Nvr.NvrBrand.Hikvision) : NetFinder.Core.Nvr.NvrBrand.Auto;
    using var e = new NetworkEngine(new Settings());
    e.LoadAdapters();
    try
    {
        var r = await NetFinder.Core.Nvr.NvrClient.ReadAsync(new Uri(args[1]), args[2], args[3], brand, CancellationToken.None);
        Console.WriteLine($"NVR brand={r.BrandName} name={r.Name} model={r.Model} serial={r.Serial} fw={r.Firmware} cams={r.Cameras.Count}");
        foreach (var c in r.Cameras)
            Console.WriteLine($"CAM ch={c.Channel} name={c.Name} ip={c.Ip} port={c.Port} model={c.Model} sn={c.Serial} mac={c.Mac} proto={c.Protocol} online={c.Online} status={c.Status}");
        foreach (var n in r.Notes) Console.WriteLine("NOTE " + n);
        var nvrDev = e.Store.ObserveIp(System.Net.IPAddress.Parse(new Uri(args[1]).Host), "Ping", null);
        Console.WriteLine("ADDED " + NetFinder.Core.Nvr.NvrClient.AddToStore(e.Store, nvrDev, r));
        foreach (var d in e.Store.All.OrderBy(d => d.Key))
            lock (d) Console.WriteLine($"DEV {d.Key,-16} type={d.Type} [{d.TypeReason}] host={d.Hostname} model={d.Model} vendor={d.Vendor} reach={d.Reachable} routed={d.Routed} nvr={d.BehindNvr} via=[{string.Join(",", d.Sources)}] info=[{string.Join("; ", d.Info.Select(kv => kv.Key + "=" + kv.Value))}]");
    }
    catch (NetFinder.Core.Nvr.NvrException ex) { Console.WriteLine($"NVRERROR wrongPassword={ex.WrongPassword} {ex.Message}"); }
    return;
}

// Model mode: NetFinder.Probe enrich <ip> <port,port,...>   (runs the port check + every enricher on one IP)
if (args.Length >= 2 && args[0] == "enrich")
{
    using var e = new NetworkEngine(new Settings { SnmpCommunities = Environment.GetEnvironmentVariable("NF_SNMP") ?? "public" });
    e.LogMessage += m => Console.WriteLine("LOG " + m);
    e.LoadAdapters();
    var ip = System.Net.IPAddress.Parse(args[1]);
    var dev = e.Store.ObserveIp(ip, "Ping", null);
    var ports = args.Length > 2 ? args[2].Split(',').Select(int.Parse).ToList() : null;
    var sw = System.Diagnostics.Stopwatch.StartNew();
    await e.CheckPortsAsync(dev, CancellationToken.None, ports);
    lock (dev)
    {
        Console.WriteLine($"DEV {dev.Key} took={sw.ElapsedMilliseconds}ms type={dev.Type} [{dev.TypeReason}] model={dev.Model} (from {dev.ModelSource}, rank {dev.ModelRank}) host={dev.Hostname} vendor={dev.Vendor} via=[{string.Join(",", dev.Sources)}] ports=[{string.Join(",", dev.OpenPorts)}]");
        foreach (var kv in dev.Info) Console.WriteLine($"     {kv.Key} = {kv.Value}");
    }
    return;
}
// IPP: NetFinder.Probe ipp <ip> [path]
if (args.Length >= 2 && args[0] == "ipp")
{
    var a = await NetFinder.Core.Net.Ipp.GetPrinterAttributesAsync(System.Net.IPAddress.Parse(args[1]), CancellationToken.None, 631, args.Length > 2 ? new[] { args[2] } : null);
    if (a == null) Console.WriteLine("IPP no answer");
    else foreach (var kv in a) Console.WriteLine($"IPP {kv.Key} = {kv.Value}");
    return;
}
// Export: NetFinder.Probe export <dir>  (sample devices → .xlsx / .csv / .html)
if (args.Length >= 2 && args[0] == "export")
{
    using var e = new NetworkEngine(new Settings());
    e.LoadAdapters();
    var a = e.Store.ObserveIp(System.Net.IPAddress.Parse("10.10.20.1"), "Ping", null, d => { d.Info["Is my gateway"] = "yes"; d.OfferModel("Archer C6 2.0", "UPnP", 75); d.Vendor = "TP-Link"; d.OpenPorts.Add(80); d.OpenPorts.Add(443); });
    e.Store.ObserveIp(System.Net.IPAddress.Parse("10.10.20.31"), "Ping", null, d => { d.OfferModel("HP LaserJet Pro M404dn", "IPP", 85); d.Info["Serial number"] = "PHBQB12345"; d.OpenPorts.Add(9100); d.Hostname = "Printer <2nd floor> & \"A\""; });
    e.Store.ObserveIp(System.Net.IPAddress.Parse("192.168.5.11"), "NVR", null, d => { d.BehindNvr = "10.10.20.64"; d.Routed = false; d.Info["NVR channel"] = "10.10.20.64  channel 1"; d.Info["Status on NVR"] = "Online"; d.OfferModel("DS-2CD1043G0-I", "NVR", 90); d.Hostname = "بوابة"; });
    e.Store.ObserveIp(System.Net.IPAddress.Parse("10.10.20.64"), "Ping", null, d => { d.Info["NVR cameras"] = "8"; d.OfferModel("DS-7608NI-K2/8P", "Hikvision API", 90); });
    e.Store.ObserveIp(System.Net.IPAddress.Parse("10.10.20.50"), "Ping", null, d => { d.Info["Windows"] = "Windows 11 Pro (10.0.22631)"; d.OfferModel("Dell OptiPlex 7090", "Windows (WMI)", 100); d.Hostname = "ACC-PC1"; });
    foreach (var ext in new[] { "xlsx", "csv", "html" })
        NetFinder.Core.Export.Exporter.Save(Path.Combine(args[1], "devices." + ext), e.Store.All, "Network devices – test");
    Console.WriteLine("EXPORTED");
    return;
}
// Changelog: NetFinder.Probe changelog
if (args.Length >= 1 && args[0] == "changelog")
{
    var all = NetFinder.Core.Update.Changelog.All;
    Console.WriteLine($"versions: {string.Join(", ", all.Select(e => e.Version))}");
    Console.WriteLine("--- one version:\n" + NetFinder.Core.Update.Changelog.Text(all.Take(1)));
    Console.WriteLine("--- two versions:\n" + NetFinder.Core.Update.Changelog.Text(all.Take(2)));
    Console.WriteLine("--- banner: " + NetFinder.Core.Update.Changelog.OneLine(string.Join("\n", all[0].Items.Select(i => "- " + i))));
    Console.WriteLine("--- banner (generated notes): [" + NetFinder.Core.Update.Changelog.OneLine("## What's Changed\n* 1.1.6 by @x in #1\n\n**Full Changelog**: https://x") + "]");
    return;
}
// Offline checks of the 1.1.8 parsers: NetFinder.Probe selftest
if (args.Length >= 1 && args[0] == "selftest")
{
    var fails = 0;
    void Check(string what, object? got, object? want)
    {
        var ok = Equals(got?.ToString(), want?.ToString());
        if (!ok) fails++;
        Console.WriteLine($"{(ok ? "OK  " : "FAIL")} {what}: {got ?? "null"}{(ok ? "" : $"   (want {want ?? "null"})")}");
    }
    // SMBIOS: header + type 0, 1, 2, 3, 17 (8 GB), 17 (32 GB extended), 17 (empty slot), 127
    var t = new List<byte>();
    void Struct(byte type, byte[] formatted, params string[] strings)
    {
        t.Add(type); t.Add((byte)(formatted.Length + 4)); t.Add(0); t.Add(0); t.AddRange(formatted);
        if (strings.Length == 0) { t.Add(0); t.Add(0); return; }
        foreach (var x in strings) { t.AddRange(System.Text.Encoding.ASCII.GetBytes(x)); t.Add(0); }
        t.Add(0);
    }
    Struct(0, new byte[] { 1, 2, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, "Dell Inc.", "1.21.0", "05/10/2024");
    // version string index 0 = "none" (SMBIOS has no empty strings)
    var t1 = new byte[0x1B - 4]; t1[0] = 1; t1[1] = 2; t1[2] = 0; t1[3] = 3; t1[0x19 - 4] = 4; t1[0x1A - 4] = 5;
    Struct(1, t1, "Dell Inc.", "OptiPlex 7090", "8XK2QJ3", "0A8E", "OptiPlex");
    Struct(2, new byte[] { 1, 2, 0, 0 }, "Dell Inc.", "0K0WPK");
    Struct(3, new byte[] { 1, 3, 0, 2 }, "Dell Inc.", "CHASSIS1");
    var m8 = new byte[0x22 - 4]; BitConverter.GetBytes((ushort)8192).CopyTo(m8, 0x0C - 4); Struct(17, m8);
    var m32 = new byte[0x22 - 4]; BitConverter.GetBytes((ushort)0x7FFF).CopyTo(m32, 0x0C - 4); BitConverter.GetBytes(32768u).CopyTo(m32, 0x1C - 4); Struct(17, m32);
    var m0 = new byte[0x22 - 4]; Struct(17, m0);
    Struct(127, Array.Empty<byte>());
    var blob = new List<byte> { 0, 3, 4, 0 }; blob.AddRange(BitConverter.GetBytes(t.Count)); blob.AddRange(t);
    var sm = NetFinder.Core.Net.Smbios.Parse(blob.ToArray());
    Check("smbios maker", sm?.Manufacturer, "Dell Inc.");
    Check("smbios product", sm?.Product, "OptiPlex 7090");
    Check("smbios version (empty string)", sm?.Version, null);
    Check("smbios serial", sm?.Serial, "8XK2QJ3");
    Check("smbios family", sm?.Family, "OptiPlex");
    Check("smbios board", $"{sm?.BoardMaker} {sm?.BoardProduct}", "Dell Inc. 0K0WPK");
    Check("smbios chassis serial", sm?.ChassisSerial, "CHASSIS1");
    Check("smbios bios", sm?.BiosVersion, "1.21.0");
    Check("smbios ram GB", sm == null ? null : sm.RamBytes / 1073741824, 40);
    Check("smbios garbage", NetFinder.Core.Net.Smbios.Parse(new byte[] { 1, 2, 3 }), null);

    // user name spellings
    string Sp(string u, string? h = null) => string.Join(" | ", NetFinder.Core.Net.WindowsNames.UserSpellings(u, h));
    Check("spell dns\\user", Sp(@"almada.local\administrator"), @"ALMADA\administrator | administrator@almada.local | almada.local\administrator");
    Check("spell dns\\user + hint", Sp(@"almada.local\administrator", "ALMADA-HQ"), @"ALMADA-HQ\administrator | ALMADA\administrator | administrator@almada.local | almada.local\administrator");
    Check("spell upn", Sp("administrator@almada.local", "ALMADA"), @"administrator@almada.local | ALMADA\administrator");
    Check("spell netbios", Sp(@"ALMADA\administrator", "ALMADA"), @"ALMADA\administrator");
    Check("spell bare", Sp("administrator"), "administrator");
    Check("spell workgroup hint ignored", Sp(@"x.local\a", "WORKGROUP"), @"X\a | a@x.local | x.local\a");

    // UPnP: software agents on PCs are not models
    NetFinder.Core.Net.UpnpDescription U(string? n, string? num) => new(null, null, n, num, null, null, null, null);
    Check("upnp HP agent", U("ProductAgent1.0", "1-00-00").Model, null);
    Check("upnp windows media", U("Windows Media Player Sharing", "12.0").Model, null);
    Check("upnp router", U("Archer C6", "2.0").Model, "Archer C6 2.0");
    Check("upnp nas", U("WDMyCloudEX4100", "BWZE").Model, "WDMyCloudEX4100 BWZE");

    // NetBIOS node status: unique <00> = PC name, group <00> = domain; "*" never becomes a name
    var ns = new List<byte>(new byte[12]); ns.Add(32); ns.AddRange(System.Text.Encoding.ASCII.GetBytes("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")); ns.Add(0);
    ns.AddRange(new byte[] { 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0 });
    var names = new (string n, byte suf, bool grp)[] { ("ALMADA", 0, true), ("AHMED-SAMY", 0, false), ("AHMED-SAMY", 0x20, false), ("ALMADA", 0x1e, true) };
    ns.Add((byte)names.Length);
    foreach (var (n, suf, grp) in names) { ns.AddRange(System.Text.Encoding.ASCII.GetBytes(n.PadRight(15))); ns.Add(suf); ns.Add((byte)(grp ? 0x84 : 0x04)); ns.Add(0); }
    var nb = NetFinder.Core.Analyzers.NetbiosAnalyzer.ParseNodeStatus(ns.ToArray(), out var grpName);
    Check("nbstat name", nb, "AHMED-SAMY");
    Check("nbstat domain", grpName, "ALMADA");
    var star = new byte[34]; star[0] = 32; var enc = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"u8.ToArray(); enc.CopyTo(star, 1);
    Check("decode '*' name", NetFinder.Core.Analyzers.NetbiosAnalyzer.DecodeName(star, out var sfx), "*");

    // classifier: Dell with only web ports is not a Windows PC; Dell with nothing open still is; iDRAC title
    var cl = new NetFinder.Core.Classifiers.BuiltInClassifier();
    string Type(Action<Device> set)
    {
        var d = new Device("10.0.0.250", "E4:43:4B:8E:19:44", System.Net.IPAddress.Parse("10.0.0.250"));
        set(d);
        var sc = new NetFinder.Core.Plugins.TypeScores();
        cl.Score(d, sc);
        return sc.Best is { Score: >= 20 } b ? b.Type : DeviceTypes.Unknown;
    }
    Check("dell 80/443/8000", Type(d => { d.Vendor = "Dell Inc."; d.PortsCheckedAt = DateTime.Now; d.OpenPorts.UnionWith(new[] { 80, 443, 8000 }); }), DeviceTypes.Linux);
    Check("dell no ports", Type(d => { d.Vendor = "Dell Inc."; d.PortsCheckedAt = DateTime.Now; }), DeviceTypes.WindowsPc);
    Check("dell 135/445", Type(d => { d.Vendor = "Dell Inc."; d.PortsCheckedAt = DateTime.Now; d.OpenPorts.UnionWith(new[] { 135, 139, 445 }); }), DeviceTypes.WindowsPc);
    Check("dell idrac title", Type(d => { d.Vendor = "Dell Inc."; d.PortsCheckedAt = DateTime.Now; d.OpenPorts.UnionWith(new[] { 80, 443 }); d.PortInfo[443] = "Integrated Dell Remote Access Controller 9"; }), DeviceTypes.Linux);
    Check("hp 135/139/445", Type(d => { d.Vendor = "Hewlett Packard"; d.PortsCheckedAt = DateTime.Now; d.OpenPorts.UnionWith(new[] { 135, 139, 445 }); }), DeviceTypes.WindowsPc);
    Console.WriteLine(fails == 0 ? "ALL OK" : $"{fails} FAILED");
    return;
}
// ONVIF multicast scan from one local address: NetFinder.Probe onvif <localIp>
if (args.Length >= 2 && args[0] == "onvif")
{
    foreach (var i in await NetFinder.Core.Net.WsDiscovery.ProbeAllAsync(System.Net.IPAddress.Parse(args[1]), 2000, CancellationToken.None))
        Console.WriteLine($"ONVIF {i.From} hw={i.Hardware} name={i.Name} loc={i.Location} types={i.Types} xaddrs={i.XAddrs}");
    return;
}

var iface = args.Length > 0 ? args[0] : "eth0";
var secs = args.Length > 1 ? int.Parse(args[1]) : 5;
var settings = new Settings { ProbeSubnets = new() { "192.168.1.0/24", "192.168.0.0/24" }, FramesPerSecond = 3000,
    ScanRanges = Environment.GetEnvironmentVariable("NF_RANGE") ?? "" };
using var eng = new NetworkEngine(settings);
eng.LogMessage += m => Console.WriteLine("LOG " + m);
eng.Store.Removed += d => Console.WriteLine("REMOVED " + d.Key);
eng.LoadAdapters();
Console.WriteLine($"capture={eng.CaptureAvailable} adapters={string.Join(" | ", eng.Adapters)}");
var ad = eng.Adapters.Where(a => a.Id == iface).ToList();
eng.StartListening(ad);
if (args.Contains("scan"))
    await eng.ScanAsync(ad, eng.Plugins.Scanners, new Progress<string>(_ => { }), CancellationToken.None);
await Task.Delay(secs * 1000);
if (args.Contains("ports"))
{
    eng.RefreshAdapterAddresses();
    foreach (var d in eng.Store.All.Where(d => d.Reachable)) await eng.CheckPortsAsync(d, CancellationToken.None);
}
foreach (var d in eng.Store.All.OrderBy(d => d.Key))
{
    lock (d)
    {
        Console.WriteLine($"DEV {d.Key,-16} mac={d.Mac} routed={d.Routed} ip={string.Join(",", d.Ips)} type={d.Type} [{d.TypeReason}] host={d.Hostname} model={d.Model} vendor={d.Vendor} reach={d.Reachable} via=[{string.Join(",", d.Sources)}] ports=[{string.Join(",", d.OpenPorts)}]");
        foreach (var kv in d.Info) Console.WriteLine($"     {kv.Key} = {kv.Value}");
        foreach (var kv in d.PortInfo) Console.WriteLine($"     port {kv.Key}: {kv.Value}");
        if (d.Services.Count > 0) Console.WriteLine($"     services: {string.Join(",", d.Services)}");
    }
}
Console.WriteLine("LEARNED " + string.Join(", ", eng.LearnedSubnets.Keys));
