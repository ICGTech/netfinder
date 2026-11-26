using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Scanners;

/// <summary>
/// ARP every address in this PC's own subnet(s) (or the part of the Range box that is on the LAN).
/// Works even when the device blocks ping. Up to 3 passes: addresses that did not answer are asked again
/// (Wi-Fi and busy switches drop broadcast floods).
/// </summary>
public sealed class LocalArpSweep : IActiveScanner
{
    public string Name => "ARP sweep of my subnet";
    public string Description => "Asks every address in this PC's own subnet who owns it. Works even when ping is blocked.";
    public int Order => 10;
    public bool RequiresCapture => true;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var a in ctx.Adapters)
        {
            foreach (var addr in a.Addresses.ToList())
            {
                var own = Ip4.ToUInt(addr.Ip);
                if ((own >> 16) == 0xA9FE && addr.Prefix == 16) continue; // 169.254 autoconfig, handled by the other-subnet probe
                var sn = addr.Subnet;
                IEnumerable<uint> hosts = ctx.Ranges.Count > 0
                    ? ctx.Ranges.SelectMany(r => r.Addresses()).Where(sn.Contains)
                    : Subnet.Of(own, Math.Max(addr.Prefix, ctx.Settings.SweepPrefixLimit)).Hosts();
                var list = hosts.Where(h => h != own && h != sn.Network && h != sn.Broadcast).Distinct()
                    .OrderBy(h => (h & 0xffffff00) == (own & 0xffffff00) ? 0 : 1) // my /24 first
                    .ToList();
                if (list.Count == 0) continue;

                for (var pass = 1; pass <= 3; pass++)
                {
                    var pending = pass == 1 ? list : list.Where(h => ctx.Store.FindByIp(Ip4.FromUInt(h)) == null).ToList();
                    if (pending.Count == 0 || (pass > 1 && pending.Count > 8192)) break;
                    ctx.Log($"ARP sweep pass {pass} on {a.FriendlyName}: {pending.Count} addresses");
                    await ctx.Engine.SendFramesAsync(a, pending.Select(h => PacketBuilder.ArpRequest(a.MacBytes, own, h)), ct,
                        n => ctx.Status.Report($"ARP sweep (pass {pass}): {n}/{pending.Count}"));
                    await Task.Delay(pass == 1 ? 1000 : 700, ct);
                }
            }
        }
    }
}
