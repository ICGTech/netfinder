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
