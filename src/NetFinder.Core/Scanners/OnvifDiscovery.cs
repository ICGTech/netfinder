using NetFinder.Core.Actions;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Scanners;

/// <summary>ONVIF WS-Discovery: every camera / NVR on the LAN answers with its model (works without Npcap).</summary>
public sealed class OnvifDiscovery : IActiveScanner
{
    public string Name => "ONVIF camera discovery";
    public string Description => "Asks IP cameras and NVRs (WS-Discovery) for their model.";
    public int Order => 32;
    public bool RequiresCapture => false;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var locals = ctx.Adapters.SelectMany(a => a.Addresses.Select(x => x.Ip)).Distinct().ToList();
        var results = await Task.WhenAll(locals.Select(async ip =>
        {
            try { return await WsDiscovery.ProbeAllAsync(ip, 2500, ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { ctx.Log($"ONVIF probe from {ip}: {ex.Message}"); return new List<OnvifInfo>(); }
        }));
        var n = 0;
        foreach (var info in results.SelectMany(r => r))
        {
            if (!Ip4.IsUsableHost(info.From)) continue;
            ctx.Store.ObserveIp(info.From, "ONVIF", null, d => OnvifEnricher.ApplyTo(d, info));
            n++;
        }
        if (n > 0) ctx.Log($"ONVIF: {n} camera(s)/NVR(s) answered");
    }
}
