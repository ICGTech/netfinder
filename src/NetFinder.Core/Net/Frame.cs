using System.Net;

namespace NetFinder.Core.Net;

/// <summary>
/// A captured Ethernet frame with the Ethernet / IPv4 / UDP layers already decoded.
/// Analyzers read the fields they need; higher layers are parsed by each analyzer.
/// </summary>
public sealed class Frame
{
    public required byte[] Data { get; init; }
    public DateTime Time { get; init; } = DateTime.Now;

    public string SrcMac { get; private set; } = "";
    public string DstMac { get; private set; } = "";
    public bool DstIsGroup { get; private set; }

    /// <summary>EtherType, or 0 for 802.3/LLC frames (then <see cref="LlcLength"/> is set).</summary>
    public ushort EtherType { get; private set; }
    public int LlcLength { get; private set; }
    public int? VlanId { get; private set; }
    public int L3Offset { get; private set; }

    public bool IsIPv4 { get; private set; }
    public IPAddress? SrcIp { get; private set; }
    public IPAddress? DstIp { get; private set; }
    public byte IpProtocol { get; private set; }
    public byte Ttl { get; private set; }
    public int L4Offset { get; private set; }
    public int L4Length { get; private set; }

    public bool IsUdp { get; private set; }
    public ushort SrcPort { get; private set; }
    public ushort DstPort { get; private set; }
    public int UdpPayloadOffset { get; private set; }
    public int UdpPayloadLength { get; private set; }

    public ReadOnlySpan<byte> L3 => Data.AsSpan(L3Offset);
    public ReadOnlySpan<byte> UdpPayload => Data.AsSpan(UdpPayloadOffset, UdpPayloadLength);

    public static Frame? Parse(byte[] data, DateTime? time = null)
    {
        if (data.Length < 14) return null;
        var f = new Frame { Data = data, Time = time ?? DateTime.Now };
        var s = data.AsSpan();
        f.DstMac = Mac.Format(s[..6]);
        f.SrcMac = Mac.Format(s.Slice(6, 6));
        f.DstIsGroup = Mac.IsGroup(s);
        var off = 12;
        var type = (ushort)(s[off] << 8 | s[off + 1]);
        while ((type == 0x8100 || type == 0x88a8) && data.Length >= off + 6)
        {
            f.VlanId = (s[off + 2] << 8 | s[off + 3]) & 0x0fff;
            off += 4;
            type = (ushort)(s[off] << 8 | s[off + 1]);
        }
        off += 2;
        f.L3Offset = off;
        if (type <= 1500) { f.LlcLength = type; f.EtherType = 0; return f; }
        f.EtherType = type;
        if (type == 0x0800) f.ParseIPv4(off);
        return f;
    }

    private void ParseIPv4(int off)
    {
        var s = Data.AsSpan();
        if (Data.Length < off + 20) return;
        if (s[off] >> 4 != 4) return;
        var ihl = (s[off] & 0x0f) * 4;
        if (ihl < 20 || Data.Length < off + ihl) return;
        var total = s[off + 2] << 8 | s[off + 3];
        if (total < ihl) return;
        var end = Math.Min(Data.Length, off + total);
        IsIPv4 = true;
        Ttl = s[off + 8];
        IpProtocol = s[off + 9];
        SrcIp = new IPAddress(s.Slice(off + 12, 4));
        DstIp = new IPAddress(s.Slice(off + 16, 4));
        L4Offset = off + ihl;
        L4Length = end - L4Offset;
        var fragOffset = (s[off + 6] & 0x1f) << 8 | s[off + 7];
        if (IpProtocol == 17 && fragOffset == 0 && L4Length >= 8)
        {
            IsUdp = true;
            SrcPort = (ushort)(s[L4Offset] << 8 | s[L4Offset + 1]);
            DstPort = (ushort)(s[L4Offset + 2] << 8 | s[L4Offset + 3]);
            UdpPayloadOffset = L4Offset + 8;
            UdpPayloadLength = Math.Max(0, L4Length - 8);
        }
    }

    public bool IsUdpPort(int port) => IsUdp && (SrcPort == port || DstPort == port);
}
