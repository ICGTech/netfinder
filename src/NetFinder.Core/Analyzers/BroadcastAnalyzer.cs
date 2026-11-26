using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Analyzers;

/// <summary>
/// Catch-all: any IPv4 broadcast/multicast packet proves a device is there with that IP —
/// whatever the protocol (vendor discovery tools, Dahua/Hikvision SADP, IGMP, LLMNR, Dropbox, games...).
/// Broadcast/multicast is never routed, so the source IP is the device's own, never a router's.
/// </summary>
public sealed class BroadcastAnalyzer : IPacketAnalyzer
{
    public string Name => "Broadcast";

    public void Analyze(Frame f, CaptureContext ctx)
    {
        if (!f.DstIsGroup) return;
        if (f.IsIPv4)
        {
            if (f.SrcIp == null || !Ip4.IsUsableHost(f.SrcIp)) { ctx.Store.Observe(f.SrcMac, "Broadcast", ctx.Adapter); return; }
            var ttl = f.Ttl;
            ctx.Store.Observe(f.SrcMac, Label(f), ctx.Adapter, f.SrcIp, d =>
            {
                // Only trust TTL from non-multicast-scoped protocols that use the OS default TTL.
                if (f.IsUdp && f.DstPort is not (5353 or 1900 or 5355) && ttl is 64 or 128 or 255) d.Info["TTL"] = ttl.ToString();
            });
            if (!ctx.Adapter.OwnsSubnetOf(f.SrcIp)) ctx.Engine.LearnSubnet(Subnet.Of(f.SrcIp, 24), $"{f.SrcIp} broadcast");
        }
        else if (f.EtherType == 0x86dd)
        {
            ctx.Store.Observe(f.SrcMac, "IPv6", ctx.Adapter);
        }
    }

    private static string Label(Frame f)
    {
        if (f.IpProtocol == 2) return "IGMP";
        if (f.IsUdp)
        {
            return (f.DstPort) switch
            {
                5355 => "LLMNR",
                67 or 68 or 137 or 138 or 1900 or 5353 => "Broadcast",
                _ => "Broadcast",
            };
        }
        return "Broadcast";
    }
}
