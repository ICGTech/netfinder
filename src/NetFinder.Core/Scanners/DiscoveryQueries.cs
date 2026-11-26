using System.Net;
using System.Text;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Scanners;

/// <summary>Asks devices to announce themselves: mDNS (Bonjour), SSDP (UPnP) and NetBIOS.</summary>
public sealed class DiscoveryQueries : IActiveScanner
{
    public string Name => "Discovery queries (mDNS, UPnP, NetBIOS)";
    public string Description => "Asks devices for their names and services.";
    public int Order => 30;
    public bool RequiresCapture => true;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var mdnsGroup = IPAddress.Parse("224.0.0.251");
        var ssdpGroup = IPAddress.Parse("239.255.255.250");
        var mdns = MdnsQuery("_services._dns-sd._udp.local", "_http._tcp.local", "_workstation._tcp.local", "_device-info._tcp.local");
        var ssdp = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n");
        var nbns = NbnsWildcardStatus();

        foreach (var a in ctx.Adapters)
        {
            var src = a.PrimaryIp;
            for (var round = 0; round < 2; round++)
            {
                ctx.Engine.SendFrame(a, PacketBuilder.Udp(a.MacBytes, PacketBuilder.MulticastMac(mdnsGroup), src, Ip4.ToUInt(mdnsGroup), 5353, 5353, mdns, 255));
                ctx.Engine.SendFrame(a, PacketBuilder.Udp(a.MacBytes, PacketBuilder.MulticastMac(ssdpGroup), src, Ip4.ToUInt(ssdpGroup), 1900, 1900, ssdp, 4));
                foreach (var addr in a.Addresses)
                    ctx.Engine.SendFrame(a, PacketBuilder.Udp(a.MacBytes, Mac.Broadcast, src, addr.Subnet.Broadcast, 137, 137, nbns));
                await Task.Delay(400, ct);
            }
        }
    }

    private static byte[] MdnsQuery(params string[] names)
    {
        var ms = new MemoryStream();
        ms.Write(new byte[] { 0, 0, 0, 0, 0, (byte)names.Length, 0, 0, 0, 0, 0, 0 });
        foreach (var n in names)
        {
            foreach (var label in n.Split('.'))
            {
                var b = Encoding.UTF8.GetBytes(label);
                ms.WriteByte((byte)b.Length); ms.Write(b);
            }
            ms.WriteByte(0);
            ms.Write(new byte[] { 0, 12, 0, 1 }); // PTR, IN (multicast reply)
        }
        return ms.ToArray();
    }

    /// <summary>NetBIOS node-status query for "*" — Windows PCs and many NAS reply with their names.</summary>
    public static byte[] NbnsWildcardStatus()
    {
        var q = new byte[50];
        q[0] = (byte)Random.Shared.Next(256); q[1] = (byte)Random.Shared.Next(256);
        q[2] = 0x00; q[3] = 0x10; // broadcast flag
        q[5] = 1;                 // 1 question
        q[12] = 32;
        var name = new byte[16]; name[0] = (byte)'*';
        for (var i = 0; i < 16; i++) { q[13 + i * 2] = (byte)('A' + (name[i] >> 4)); q[14 + i * 2] = (byte)('A' + (name[i] & 0xf)); }
        q[45] = 0;
        q[46] = 0; q[47] = 0x21; // NBSTAT
        q[48] = 0; q[49] = 1;
        return q;
    }
}
