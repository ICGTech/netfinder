using System.Net;
using System.Net.Sockets;

namespace NetFinder.Core.Net;

/// <summary>An inclusive range of IPv4 addresses, typed by the user in the Range box.</summary>
public readonly record struct IpRange(uint Start, uint End)
{
    public long Count => (long)End - Start + 1;
    public bool Contains(uint ip) => ip >= Start && ip <= End;

    public IEnumerable<uint> Addresses()
    {
        for (var v = Start; ; v++)
        {
            if (Ip4.IsUsableHost(v) && (v & 0xff) != 0 && (v & 0xff) != 255) yield return v;
            if (v == End) yield break;
        }
    }

    public override string ToString() => Start == End ? Ip4.FromUInt(Start).ToString() : $"{Ip4.FromUInt(Start)} - {Ip4.FromUInt(End)}";

    public const long MaxAddresses = 65536;

    /// <summary>
    /// Accepts a list separated by commas/spaces. Each item can be:
    /// 10.10.0.0/16 · 10.10.20.1-254 · 10.10.20.1-10.10.21.254 · 10.10.20.* · 10.10.20.7
    /// </summary>
    public static bool TryParseList(string? text, out List<IpRange> ranges, out string? error)
    {
        ranges = new List<IpRange>();
        error = null;
        if (string.IsNullOrWhiteSpace(text)) return true;
        foreach (var raw in text.Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (!TryParseOne(raw.Trim(), out var r)) { error = $"\"{raw}\" is not a valid range. Examples: 10.10.20.0/24, 10.10.20.1-254, 10.10.20.*"; return false; }
            ranges.Add(r);
        }
        var total = ranges.Sum(r => r.Count);
        if (total > MaxAddresses) { error = $"The range has {total:N0} addresses; the limit is {MaxAddresses:N0} (a /16)."; return false; }
        return true;
    }

    private static bool TryParseOne(string s, out IpRange r)
    {
        r = default;
        if (s.EndsWith(".*"))
            s = s[..^2] + ".0/24";
        if (s.Contains('/'))
        {
            if (!Subnet.TryParse(s, out var sn) || sn.Prefix < 16) return false;
            r = sn.Prefix >= 31 ? new IpRange(sn.Network, sn.Broadcast) : new IpRange(sn.Network + 1, sn.Broadcast - 1);
            return true;
        }
        var dash = s.IndexOf('-');
        if (dash < 0)
        {
            if (!TryIp(s, out var one)) return false;
            r = new IpRange(one, one);
            return true;
        }
        var left = s[..dash].Trim(); var right = s[(dash + 1)..].Trim();
        if (!TryIp(left, out var start)) return false;
        uint end;
        if (int.TryParse(right, out var lastOctet) && lastOctet is >= 0 and <= 255 && !right.Contains('.'))
            end = (start & 0xffffff00) | (uint)lastOctet;
        else if (!TryIp(right, out end)) return false;
        if (end < start) return false;
        r = new IpRange(start, end);
        return true;
    }

    private static bool TryIp(string s, out uint v)
    {
        v = 0;
        if (s.Count(c => c == '.') != 3 || !IPAddress.TryParse(s, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) return false;
        v = Ip4.ToUInt(ip);
        return true;
    }
}
