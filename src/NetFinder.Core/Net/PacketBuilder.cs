using System.Net;

namespace NetFinder.Core.Net;

/// <summary>Builds raw Ethernet frames for active probing.</summary>
public static class PacketBuilder
{
    /// <summary>
    /// ARP request "who has targetIp". Use senderIp = 0.0.0.0 for an RFC 5227 ARP probe: devices answer it
    /// even when we are on a completely different subnet, and it does not pollute anyone's ARP cache.
    /// </summary>
    public static byte[] ArpRequest(byte[] srcMac, uint senderIp, uint targetIp)
    {
        var f = new byte[42];
        Mac.Broadcast.CopyTo(f, 0);
        srcMac.CopyTo(f, 6);
        f[12] = 0x08; f[13] = 0x06;
        f[14] = 0; f[15] = 1;          // htype ethernet
        f[16] = 0x08; f[17] = 0;       // ptype ipv4
        f[18] = 6; f[19] = 4;
        f[20] = 0; f[21] = 1;          // request
        srcMac.CopyTo(f, 22);
        Ip4.Write(senderIp, f.AsSpan(28));
        // target mac zero
        Ip4.Write(targetIp, f.AsSpan(38));
        return f;
    }

    public static byte[] Udp(byte[] srcMac, byte[] dstMac, uint srcIp, uint dstIp, ushort srcPort, ushort dstPort, ReadOnlySpan<byte> payload, byte ttl = 64)
    {
        var len = 14 + 20 + 8 + payload.Length;
        var f = new byte[len];
        dstMac.CopyTo(f, 0);
        srcMac.CopyTo(f, 6);
        f[12] = 0x08; f[13] = 0x00;
        var ip = f.AsSpan(14, 20);
        ip[0] = 0x45;
        var total = 20 + 8 + payload.Length;
        ip[2] = (byte)(total >> 8); ip[3] = (byte)total;
        ip[4] = (byte)Random.Shared.Next(256); ip[5] = (byte)Random.Shared.Next(256);
        ip[8] = ttl; ip[9] = 17;
        Ip4.Write(srcIp, ip[12..]);
        Ip4.Write(dstIp, ip[16..]);
        var sum = Checksum(ip);
        ip[10] = (byte)(sum >> 8); ip[11] = (byte)sum;
        var udp = f.AsSpan(34);
        udp[0] = (byte)(srcPort >> 8); udp[1] = (byte)srcPort;
        udp[2] = (byte)(dstPort >> 8); udp[3] = (byte)dstPort;
        var ul = 8 + payload.Length;
        udp[4] = (byte)(ul >> 8); udp[5] = (byte)ul;
        // UDP checksum 0 = not used (allowed for IPv4)
        payload.CopyTo(udp[8..]);
        return f;
    }

    /// <summary>Ethernet multicast MAC for an IPv4 multicast group.</summary>
    public static byte[] MulticastMac(IPAddress group)
    {
        var b = group.GetAddressBytes();
        return new byte[] { 0x01, 0x00, 0x5e, (byte)(b[1] & 0x7f), b[2], b[3] };
    }

    public static ushort Checksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        for (var i = 0; i + 1 < data.Length; i += 2) sum += (uint)(data[i] << 8 | data[i + 1]);
        if ((data.Length & 1) == 1) sum += (uint)(data[^1] << 8);
        while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
        return (ushort)~sum;
    }
}
