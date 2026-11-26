using System.Text;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Analyzers;

/// <summary>SSDP / UPnP (UDP 1900): routers, TVs, NAS, cameras, printers announce SERVER and a description URL.</summary>
public sealed class SsdpAnalyzer : IPacketAnalyzer
{
    public string Name => "SSDP";

    public void Analyze(Frame f, CaptureContext ctx)
    {
        if (!f.IsUdp || f.SrcIp == null || (f.SrcPort != 1900 && f.DstPort != 1900)) return;
        var text = Encoding.UTF8.GetString(f.UdpPayload);
        if (!(text.StartsWith("NOTIFY", StringComparison.OrdinalIgnoreCase) || text.StartsWith("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase)
              || text.StartsWith("M-SEARCH", StringComparison.OrdinalIgnoreCase))) return;
        var isSearch = text.StartsWith("M-SEARCH", StringComparison.OrdinalIgnoreCase);
        string? server = null, location = null;
        foreach (var line in text.Split('\n'))
        {
            var c = line.IndexOf(':');
            if (c <= 0) continue;
            var k = line[..c].Trim(); var v = line[(c + 1)..].Trim();
            if (k.Equals("SERVER", StringComparison.OrdinalIgnoreCase)) server = v;
            else if (k.Equals("LOCATION", StringComparison.OrdinalIgnoreCase)) location = v;
            else if (k.Equals("USER-AGENT", StringComparison.OrdinalIgnoreCase) && isSearch) server ??= v;
        }
        ctx.Store.Observe(f.SrcMac, "SSDP", ctx.Adapter, f.SrcIp, d =>
        {
            if (server != null) d.Info[isSearch ? "UPnP client" : "UPnP server"] = server;
            if (location != null) d.Info["UPnP description URL"] = location;
        });
    }
}
