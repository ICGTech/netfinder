using System.Collections.Concurrent;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Scanners;

/// <summary>
/// No-Npcap mode: uses the Windows SendARP API on every address of the local subnet.
/// Finds devices that block ping (phones, firewalled PCs) because every IPv4 device must answer ARP.
/// Only runs when Npcap is not available (with Npcap, LocalArpSweep does the same thing faster).
/// </summary>
public sealed class WindowsArpSweep : IActiveScanner
{
    public string Name => "Windows ARP sweep (no Npcap)";
    public string Description => "SendARP to every address of my subnet, using Windows itself.";
    public int Order => 12;
    public bool RequiresCapture => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        if (ctx.Engine.CaptureAvailable || !OperatingSystem.IsWindows()) return;
        foreach (var a in ctx.Adapters)
        foreach (var addr in a.Addresses.ToList())
        {
            var own = Ip4.ToUInt(addr.Ip);
            var sn = addr.Subnet;
            IEnumerable<uint> hosts = ctx.Ranges.Count > 0
                ? ctx.Ranges.SelectMany(r => r.Addresses()).Where(sn.Contains)
                : Subnet.Of(own, Math.Max(addr.Prefix, 22)).Hosts(); // SendARP is slow (3 s per free address): cap at /22
            var list = hosts.Where(h => h != own && h != sn.Network && h != sn.Broadcast).Distinct().ToList();
            if (list.Count == 0) continue;

            for (var pass = 1; pass <= 2; pass++)
            {
                var queue = new ConcurrentQueue<uint>(pass == 1 ? list : list.Where(h => ctx.Store.FindByIp(Ip4.FromUInt(h)) == null));
                var total = queue.Count;
                if (total == 0) break;
                ctx.Log($"Windows ARP sweep pass {pass} on {a.FriendlyName}: {total} addresses");
                var done = 0;
                var workers = Enumerable.Range(0, Math.Min(192, total)).Select(_ => Task.Factory.StartNew(() =>
                {
                    while (!ct.IsCancellationRequested && queue.TryDequeue(out var h))
                    {
                        var ip = Ip4.FromUInt(h);
                        var mac = WindowsNet.ResolveMac(ip, addr.Ip);
                        if (mac != null) ctx.Store.Observe(mac, "ARP", a, ip);
                        var n = Interlocked.Increment(ref done);
                        if (n % 16 == 0) ctx.Status.Report($"Windows ARP sweep (pass {pass}): {n}/{total}");
                    }
                }, ct, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();
                await Task.WhenAll(workers);
                ct.ThrowIfCancellationRequested();
            }
        }
    }
}
