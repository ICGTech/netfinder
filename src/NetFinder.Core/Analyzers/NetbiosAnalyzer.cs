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
        string? name = null;
        if (f.SrcPort == 137 && f.DstPort == 137 && p.Length >= 12 + 34)
        {
            var flags = p[2] << 8 | p[3];
            var isResponse = (flags & 0x8000) != 0;
            var opcode = (flags >> 11) & 0xf;
            // registration (5), refresh (8/9) and responses carry the sender's own name
            if (opcode is 5 or 8 or 9 || isResponse) name = DecodeName(p.Slice(12));
            else { ctx.Store.Observe(f.SrcMac, "NetBIOS", ctx.Adapter, f.SrcIp); return; }
        }
        else if (f.SrcPort == 138 && f.DstPort == 138 && p.Length >= 14 + 34)
        {
            name = DecodeName(p.Slice(14));
        }
        if (string.IsNullOrWhiteSpace(name)) return;
        ctx.Store.Observe(f.SrcMac, "NetBIOS", ctx.Adapter, f.SrcIp, d =>
        {
            if (name.Contains("__MSBROWSE__")) return;
            d.Info["NetBIOS name"] = name;
            d.Hostname ??= name;
        });
    }

    /// <summary>Decodes the 32-char "half-ASCII" NetBIOS name; drops the 16th suffix byte.</summary>
    public static string? DecodeName(ReadOnlySpan<byte> s)
    {
        if (s.Length < 33 || s[0] != 32) return null;
        var b = new byte[16];
        for (var i = 0; i < 16; i++)
        {
            int hi = s[1 + i * 2] - 'A', lo = s[2 + i * 2] - 'A';
            if (hi is < 0 or > 15 || lo is < 0 or > 15) return null;
            b[i] = (byte)(hi << 4 | lo);
        }
        var str = Encoding.ASCII.GetString(b, 0, 15).Trim().TrimEnd('\0');
        return str.Length == 0 || str.Any(ch => ch < 32) ? null : str;
    }
}
