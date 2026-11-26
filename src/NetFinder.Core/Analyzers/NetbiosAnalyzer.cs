using System.Text;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Analyzers;

/// <summary>NetBIOS name service (137) and datagram/browser (138): Windows PC names and workgroups.</summary>
public sealed class NetbiosAnalyzer : IPacketAnalyzer
{
    public string Name => "NetBIOS";

    public void Analyze(Frame f, CaptureContext ctx)
    {
        if (!f.IsUdp || f.SrcIp == null) return;
        var p = f.UdpPayload;
        string? name = null, group = null;
        if (f.SrcPort == 137 && f.DstPort == 137 && p.Length >= 12 + 34)
        {
            var flags = p[2] << 8 | p[3];
            var isResponse = (flags & 0x8000) != 0;
            var opcode = (flags >> 11) & 0xf;
            if (isResponse && p.Length >= 12 + 34 + 2 && (p[46] << 8 | p[47]) == 0x21)
            {
                // node status answer (to the "*" query): the list of the PC's names
                name = ParseNodeStatus(p.ToArray(), out group);
            }
            else if (opcode is 5 or 8 or 9 || isResponse)
            {
                // registration (5), refresh (8/9) and responses carry the sender's own name… or its workgroup / domain (group names)
                name = DecodeName(p.Slice(12), out var suffix);
                var flagsAt = isResponse ? 56 : p.Length > 50 && p[50] == 0xC0 ? 62 : -1;
                var isGroup = flagsAt > 0 && p.Length > flagsAt && (p[flagsAt] & 0x80) != 0;
                if (isGroup) { if (suffix == 0) group = name; name = null; }
                else if (suffix is not (0x00 or 0x20)) name = null;
            }
            else { ctx.Store.Observe(f.SrcMac, "NetBIOS", ctx.Adapter, f.SrcIp); return; }
        }
        else if (f.SrcPort == 138 && f.DstPort == 138 && p.Length >= 14 + 34)
        {
            name = DecodeName(p.Slice(14), out var suffix);
            if (suffix is not (0x00 or 0x20)) name = null;
        }
        if (name == "*" || name?.Contains("__MSBROWSE__") == true) name = null;
        if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(group)) return;
        ctx.Store.Observe(f.SrcMac, "NetBIOS", ctx.Adapter, f.SrcIp, d =>
        {
            if (!string.IsNullOrWhiteSpace(name))
            {
                d.Info["NetBIOS name"] = name;
                // an earlier wrong guess ("*", or the domain name) gives way
                if (d.Hostname == null || d.Hostname == "*" || d.Hostname.Equals(d.Info.GetValueOrDefault("Workgroup / domain"), StringComparison.OrdinalIgnoreCase))
                    d.Hostname = name;
            }
            if (!string.IsNullOrWhiteSpace(group)) d.Info["Workgroup / domain"] = group;
        });
    }

    /// <summary>
    /// Names in a NetBIOS node status answer: the PC's own name (unique &lt;00&gt; or &lt;20&gt;) and its workgroup / domain (group &lt;00&gt;).
    /// </summary>
    public static string? ParseNodeStatus(byte[] b, out string? group)
    {
        group = null;
        // header 12, name 34, type/class 4, ttl 4, rdlength 2, then count
        var off = 12 + 34 + 4 + 4 + 2;
        if (b.Length <= off) return null;
        int count = b[off++];
        string? name = null, server = null;
        for (var i = 0; i < count && off + 18 <= b.Length; i++, off += 18)
        {
            var n = Encoding.ASCII.GetString(b, off, 15).TrimEnd(' ', '\0').Trim();
            if (n.Length == 0 || n.Any(ch => ch < 32)) continue;
            var suffix = b[off + 15];
            var isGroup = (b[off + 16] & 0x80) != 0;
            if (suffix == 0 && !isGroup) name ??= n;
            if (suffix == 0x20 && !isGroup) server ??= n;
            if (suffix == 0 && isGroup) group ??= n;
        }
        return name ?? server;
    }

    public static string? DecodeName(ReadOnlySpan<byte> s) => DecodeName(s, out _);

    /// <summary>Decodes the 32-char "half-ASCII" NetBIOS name; drops the 16th suffix byte.</summary>
    public static string? DecodeName(ReadOnlySpan<byte> s, out byte suffix)
    {
        suffix = 0xff;
        if (s.Length < 33 || s[0] != 32) return null;
        var b = new byte[16];
        for (var i = 0; i < 16; i++)
        {
            int hi = s[1 + i * 2] - 'A', lo = s[2 + i * 2] - 'A';
            if (hi is < 0 or > 15 || lo is < 0 or > 15) return null;
            b[i] = (byte)(hi << 4 | lo);
        }
        suffix = b[15];
        var str = Encoding.ASCII.GetString(b, 0, 15).TrimEnd(' ', '\0').Trim();
        return str.Length == 0 || str.Any(ch => ch < 32) ? null : str;
    }
}
