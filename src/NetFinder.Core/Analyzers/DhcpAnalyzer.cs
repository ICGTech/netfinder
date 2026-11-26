using System.Net;
using System.Text;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Analyzers;

/// <summary>
/// DHCP: a device set to DHCP with no server around still broadcasts DISCOVER/REQUEST
/// with its MAC, hostname, vendor class and (option 50) the last IP it had.
/// DHCP servers' OFFERs reveal rogue/unknown DHCP servers too.
/// </summary>
public sealed class DhcpAnalyzer : IPacketAnalyzer
{
    public string Name => "DHCP";

    private static readonly string[] MsgTypes = { "", "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NAK", "RELEASE", "INFORM" };

    public void Analyze(Frame f, CaptureContext ctx)
    {
        if (!f.IsUdp || !((f.SrcPort == 68 && f.DstPort == 67) || (f.SrcPort == 67 && f.DstPort == 68))) return;
        var p = f.UdpPayload;
        if (p.Length < 240 || p[236] != 99 || p[237] != 130 || p[238] != 83 || p[239] != 99) return;
        var op = p[0];
        var ciaddr = new IPAddress(p.Slice(12, 4));
        var yiaddr = new IPAddress(p.Slice(16, 4));
        var chaddr = Mac.Format(p.Slice(28, 6));

        int msgType = 0; string? host = null, vendor = null; IPAddress? requested = null, serverId = null, router = null; int? prefix = null;
        var i = 240;
        while (i < p.Length)
        {
            var code = p[i++];
            if (code == 0) continue;
            if (code == 255 || i >= p.Length) break;
            var len = p[i++];
            if (i + len > p.Length) break;
            var v = p.Slice(i, len);
            switch (code)
            {
                case 53 when len >= 1: msgType = v[0]; break;
                case 12: host = Clean(v); break;
                case 60: vendor = Clean(v); break;
                case 50 when len == 4: requested = new IPAddress(v); break;
                case 54 when len == 4: serverId = new IPAddress(v); break;
                case 3 when len >= 4: router = new IPAddress(v[..4]); break;
                case 1 when len == 4: prefix = System.Numerics.BitOperations.PopCount(Ip4.ToUInt(v)); break;
            }
            i += len;
        }
        var type = msgType < MsgTypes.Length ? MsgTypes[msgType] : msgType.ToString();

        if (op == 1)
        {
            // client -> server. Use chaddr (real client MAC even through relays).
            var ip = Ip4.IsUsableHost(ciaddr) ? ciaddr : null;
            ctx.Store.Observe(chaddr, "DHCP", ctx.Adapter, ip, d =>
            {
                if (host != null) d.Hostname = host;
                if (vendor != null) d.Info["DHCP vendor class"] = vendor;
                if (requested != null) d.Info["DHCP asked for IP"] = requested.ToString();
                d.Info["DHCP last message"] = $"{type} at {f.Time:HH:mm:ss}";
                d.Info["Uses DHCP"] = "yes";
            });
        }
        else if (op == 2)
        {
            // server -> client
            ctx.Store.Observe(f.SrcMac, "DHCP server", ctx.Adapter, serverId ?? f.SrcIp, d =>
            {
                d.Info["DHCP server"] = "yes" + (router != null ? $", gateway {router}" : "") + (prefix != null ? $", /{prefix}" : "");
            });
            if (Ip4.IsUsableHost(yiaddr))
                ctx.Store.Observe(chaddr, "DHCP", ctx.Adapter, yiaddr, d => d.Info["DHCP assigned IP"] = $"{yiaddr} ({type})");
            if (serverId != null && prefix != null) ctx.Engine.LearnSubnet(Subnet.Of(serverId, prefix.Value), "DHCP server");
        }
    }

    private static string Clean(ReadOnlySpan<byte> v) => Encoding.ASCII.GetString(v).TrimEnd('\0').Trim();
}
