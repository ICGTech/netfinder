using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Analyzers;

/// <summary>mDNS / Bonjour (UDP 5353): hostnames (*.local), model names and offered services.</summary>
public sealed class MdnsAnalyzer : IPacketAnalyzer
{
    public string Name => "mDNS";

    private static readonly string[] ModelKeys = { "md", "model", "am", "ty", "usb_MDL", "product", "mdl" };

    public void Analyze(Frame f, CaptureContext ctx)
    {
        if (!f.IsUdp || f.SrcPort != 5353 && f.DstPort != 5353 || f.SrcIp == null) return;
        var msg = DnsMessage.Parse(f.UdpPayload);
        if (msg == null) return;

        string? host = null, model = null, friendly = null;
        var services = new HashSet<string>();
        foreach (var r in msg.Records)
        {
            if (r.Type == 1 && r.Address != null && r.Address.Equals(f.SrcIp)) host = StripLocal(r.Name);
            else if (r.Type == 12 && !r.Name.StartsWith("_services._dns-sd", StringComparison.OrdinalIgnoreCase) && r.Name.StartsWith('_'))
            {
                services.Add(StripLocal(r.Name));
                if (r.Target != null) friendly ??= r.Target.Split("._")[0];
            }
            else if (r.Type == 33 && r.Target != null) host ??= StripLocal(r.Target);
            else if (r.Type == 16 && r.Txt != null)
            {
                foreach (var kv in r.Txt)
                {
                    var eq = kv.IndexOf('=');
                    if (eq <= 0) continue;
                    var k = kv[..eq]; var v = kv[(eq + 1)..];
                    if (v.Length == 0) continue;
                    if (ModelKeys.Contains(k, StringComparer.OrdinalIgnoreCase)) model ??= v.Trim();
                    if (k.Equals("fn", StringComparison.OrdinalIgnoreCase)) friendly ??= v;
                }
            }
        }
        if (!msg.IsResponse && host == null && services.Count == 0) {
            // plain query: still proves the device exists at this IP
            ctx.Store.Observe(f.SrcMac, "mDNS", ctx.Adapter, f.SrcIp);
            return;
        }
        ctx.Store.Observe(f.SrcMac, "mDNS", ctx.Adapter, f.SrcIp, d =>
        {
            if (host != null) { d.Hostname ??= host; d.Info["mDNS name"] = host + ".local"; }
            if (model != null) d.OfferModel(model, "mDNS", 60);
            if (friendly != null) d.Info["mDNS friendly name"] = friendly;
            foreach (var s in services) d.Services.Add(s);
        });
    }

    private static string StripLocal(string n) => n.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ? n[..^6] : n;
}
