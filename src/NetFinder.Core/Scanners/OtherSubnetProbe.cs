using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Scanners;

/// <summary>
/// THE key feature: finds devices whose IP is in a different subnet from this PC
/// (e.g. a camera on 192.168.1.64 plugged into a 10.10.20.x network).
/// Sends RFC 5227 ARP probes (sender IP 0.0.0.0) for every address of common factory-default
/// subnets plus subnets learned from passive listening. Devices answer probes for their own IP
/// no matter what subnet we are on, and probes don't change anyone's ARP cache.
/// </summary>
public sealed class OtherSubnetProbe : IActiveScanner
{
    public string Name => "Probe other subnets";
    public string Description => "ARP-probes common default subnets (192.168.0/1.x, 10.0.0.x …) and subnets heard on the wire.";
    public int Order => 20;
    public bool RequiresCapture => true;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var subnets = new List<Subnet>();
        foreach (var s in ctx.Settings.ProbeSubnets)
            if (Subnet.TryParse(s, out var sn)) subnets.Add(sn);
        if (ctx.Settings.ProbeLearnedSubnets) subnets.AddRange(ctx.Engine.LearnedSubnets.Keys);
        if (ctx.Settings.ProbeLinkLocal) subnets.Add(new Subnet(0xA9FE0000, 16));
        if (ctx.Settings.DeepScan) subnets.Add(new Subnet(0xC0A80000, 16)); // all of 192.168.x.x
        subnets = subnets.Distinct().ToList();
        // drop subnets fully contained in a bigger one already in the list
        subnets = subnets.Where(s => !subnets.Any(o => o != s && o.Prefix < s.Prefix && o.Contains(s.Network))).ToList();

        foreach (var a in ctx.Adapters)
        {
            var mine = a.Addresses.Select(x => x.Subnet).ToList();
            var targets = subnets.Where(s => !mine.Any(m => m.Overlaps(s))).ToList();
            var total = targets.Sum(t => t.HostCount);
            ctx.Log($"Probing {targets.Count} other subnets ({total} addresses) on {a.FriendlyName}");
            var frames = targets.SelectMany(t => t.Hosts()).Select(h => PacketBuilder.ArpRequest(a.MacBytes, 0, h));
            await ctx.Engine.SendFramesAsync(a, frames, ct, n => ctx.Status.Report($"Probing other subnets: {n}/{total}"));
        }
    }
}
