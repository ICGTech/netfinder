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
