using System.Net;
using System.Net.Sockets;

namespace NetFinder.Core.Net;

public static class Ip4
{
    public static uint ToUInt(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static uint ToUInt(ReadOnlySpan<byte> b) => ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];

    public static IPAddress FromUInt(uint v) => new(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });

    public static void Write(uint v, Span<byte> dst)
    {
        dst[0] = (byte)(v >> 24); dst[1] = (byte)(v >> 16); dst[2] = (byte)(v >> 8); dst[3] = (byte)v;
    }

    public static uint MaskFromPrefix(int prefix) => prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);

    public static bool IsUsableHost(uint v)
    {
        if (v == 0 || v == uint.MaxValue) return false;
        var first = v >> 24;
        if (first == 127 || first >= 224 || first == 0) return false;
        return true;
    }

    public static bool IsUsableHost(IPAddress ip) => ip.AddressFamily == AddressFamily.InterNetwork && IsUsableHost(ToUInt(ip));
}

/// <summary>An IPv4 network such as 192.168.1.0/24.</summary>
public readonly record struct Subnet(uint Network, int Prefix)
{
    public uint Mask => Ip4.MaskFromPrefix(Prefix);
    public uint Broadcast => Network | ~Mask;
    public bool Contains(uint ip) => (ip & Mask) == Network;
    public bool Contains(IPAddress ip) => ip.AddressFamily == AddressFamily.InterNetwork && Contains(Ip4.ToUInt(ip));
    public bool Overlaps(Subnet o) => Contains(o.Network) || o.Contains(Network);
    public long HostCount => Prefix >= 31 ? (1L << (32 - Prefix)) : (1L << (32 - Prefix)) - 2;

    public IEnumerable<uint> Hosts()
    {
        if (Prefix >= 31) { for (var v = Network; v <= Broadcast && v >= Network; v++) { yield return v; if (v == uint.MaxValue) yield break; } yield break; }
        for (var v = Network + 1; v < Broadcast; v++) yield return v;
    }

    public static Subnet Of(uint ip, int prefix) => new(ip & Ip4.MaskFromPrefix(prefix), prefix);
    public static Subnet Of(IPAddress ip, int prefix) => Of(Ip4.ToUInt(ip), prefix);

    public static bool TryParse(string s, out Subnet subnet)
    {
        subnet = default;
        s = s.Trim();
        var parts = s.Split('/');
        if (!IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var prefix = 24;
        if (parts.Length > 1 && (!int.TryParse(parts[1], out prefix) || prefix < 8 || prefix > 32)) return false;
        subnet = Of(ip, prefix);
        return true;
    }

    public override string ToString() => $"{Ip4.FromUInt(Network)}/{Prefix}";
}
