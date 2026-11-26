using System.Net;
using System.Text;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Analyzers;

/// <summary>
/// LLDP (all managed switches, IP phones, APs) and Cisco CDP: system name, model,
/// port, and the management IP — even when that IP is in a totally different subnet.
/// </summary>
public sealed class LldpCdpAnalyzer : IPacketAnalyzer
{
    public string Name => "LLDP/CDP";

    public void Analyze(Frame f, CaptureContext ctx)
    {
        if (f.EtherType == 0x88cc) Lldp(f, ctx);
        else if (f.EtherType == 0 && f.DstMac == "01:00:0C:CC:CC:CC") Cdp(f, ctx);
    }

    private static void Lldp(Frame f, CaptureContext ctx)
    {
        var s = f.L3;
        var i = 0;
        string? sysName = null, sysDesc = null, port = null; IPAddress? mgmt = null;
        while (i + 2 <= s.Length)
        {
            var type = s[i] >> 1;
            var len = (s[i] & 1) << 8 | s[i + 1];
            i += 2;
            if (type == 0 || i + len > s.Length) break;
            var v = s.Slice(i, len);
            switch (type)
            {
                case 2 when len > 1: port = Text(v[1..]); break;
                case 4: port = Text(v) + (port != null ? $" ({port})" : ""); break;
                case 5: sysName = Text(v); break;
                case 6: sysDesc = Text(v); break;
                case 8 when len >= 6 && v[1] == 1 && v[0] == 5: mgmt ??= new IPAddress(v.Slice(2, 4)); break;
            }
            i += len;
        }
        ctx.Store.Observe(f.SrcMac, "LLDP", ctx.Adapter, mgmt, d =>
        {
            if (sysName != null) d.Hostname ??= sysName;
            if (sysDesc != null) { d.Info["LLDP description"] = sysDesc; d.Model ??= sysDesc.Split('\n')[0]; }
            if (port != null) d.Info["Connected to its port"] = port;
            if (mgmt != null) d.Info["LLDP management IP"] = mgmt.ToString();
        });
    }

    private static void Cdp(Frame f, CaptureContext ctx)
    {
        var s = f.L3;
        // LLC/SNAP AA AA 03 00 00 0C 20 00
        if (s.Length < 12 || s[0] != 0xAA || s[1] != 0xAA || s[6] != 0x20 || s[7] != 0x00) return;
        var i = 8 + 4; // version, ttl, checksum
        string? devId = null, port = null, platform = null, software = null; IPAddress? addr = null;
        while (i + 4 <= s.Length)
        {
            var type = s[i] << 8 | s[i + 1];
            var len = s[i + 2] << 8 | s[i + 3];
            if (len < 4 || i + len > s.Length) break;
            var v = s.Slice(i + 4, len - 4);
            switch (type)
            {
                case 1: devId = Text(v); break;
                case 3: port = Text(v); break;
                case 5: software = Text(v); break;
                case 6: platform = Text(v); break;
                case 2 or 0x16 when v.Length >= 13: // addresses / mgmt addresses
                    if (v[4] == 1 && v[5] == 1 && v[6] == 0xCC && (v[7] << 8 | v[8]) == 4) addr ??= new IPAddress(v.Slice(9, 4));
                    break;
            }
            i += len;
        }
        ctx.Store.Observe(f.SrcMac, "CDP", ctx.Adapter, addr, d =>
        {
            if (devId != null) d.Hostname ??= devId;
            if (platform != null) d.Model ??= platform;
            if (port != null) d.Info["Connected to its port"] = port;
            if (software != null) d.Info["CDP software"] = software.Split('\n')[0];
        });
    }

    private static string Text(ReadOnlySpan<byte> v) => Encoding.UTF8.GetString(v).Trim('\0', ' ', '\r', '\n');
}
