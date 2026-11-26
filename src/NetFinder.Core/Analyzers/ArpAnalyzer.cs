using System.Net;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Analyzers;

/// <summary>
/// ARP is the most important source: every IPv4 device ARPs, whatever its subnet.
/// A device on 192.168.1.x plugged into our 10.10.20.x LAN still broadcasts
/// "who has 192.168.1.1?" (its gateway) — which tells us its IP, MAC and subnet.
/// </summary>
public sealed class ArpAnalyzer : IPacketAnalyzer
{
    public string Name => "ARP";

    public void Analyze(Frame f, CaptureContext ctx)
    {
        if (f.EtherType != 0x0806) return;
        var a = f.L3;
        if (a.Length < 28 || a[4] != 6 || a[5] != 4) return;
        var op = a[6] << 8 | a[7];
        var senderMac = Mac.Format(a.Slice(8, 6));
        var senderIp = Ip4.ToUInt(a.Slice(14, 4));
        var targetIp = Ip4.ToUInt(a.Slice(24, 4));

        if (senderIp == 0)
        {
            // ARP probe (duplicate address detection): device is about to use targetIp
            ctx.Store.Observe(senderMac, "ARP", ctx.Adapter, null, d =>
                d.Info["ARP probe for"] = Ip4.FromUInt(targetIp).ToString());
            return;
        }

        var sip = Ip4.FromUInt(senderIp);
        ctx.Store.Observe(senderMac, "ARP", ctx.Adapter, sip, d =>
        {
            if (senderIp == targetIp) d.Info["Gratuitous ARP"] = "yes";
            else if (op == 1)
            {
                d.Info["Last ARP lookup"] = Ip4.FromUInt(targetIp).ToString();
            }
        });

        // Learn the subnet of foreign devices so we can probe their neighbours too.
        if (op == 1 && senderIp != targetIp && (senderIp & 0xffffff00) == (targetIp & 0xffffff00))
            ctx.Engine.LearnSubnet(Subnet.Of(senderIp, 24), $"{sip} asked for {Ip4.FromUInt(targetIp)}");
        else if (!ctx.Adapter.OwnsSubnetOf(sip))
            ctx.Engine.LearnSubnet(Subnet.Of(senderIp, 24), $"{sip} seen via ARP");
    }
}
