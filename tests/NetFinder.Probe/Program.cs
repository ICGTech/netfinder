// Console harness used to test the engine on Linux/Windows without the GUI.
// usage: NetFinder.Probe <interface> [listenSeconds] [scan] [ports]
using NetFinder.Core;
using NetFinder.Core.Model;

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
