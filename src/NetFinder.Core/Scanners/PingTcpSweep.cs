using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetFinder.Core.Model;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Scanners;

/// <summary>
/// Ping + TCP sweep (what Advanced IP Scanner does). Complements ARP:
/// - finds devices behind a router (other VLANs / routed ranges typed in the Range box),
/// - works without Npcap (then it is the only scanner, and MACs come from the Windows ARP table),
/// - devices that ignore ping are tried on common TCP ports; even a "connection refused" proves the host is alive.
/// </summary>
public sealed class PingTcpSweep : IActiveScanner
{
    public string Name => "Ping + TCP sweep";
    public string Description => "Pings every address (and tries common TCP ports on routed ranges). Also reads the Windows ARP table.";
    public int Order => 15;
    public bool RequiresCapture => false;

    private static readonly int[] AlivePorts = { 80, 443, 22, 445, 3389, 8080, 554, 9100, 23, 8000 };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var own = ctx.Adapters.SelectMany(a => a.Addresses).Select(a => Ip4.ToUInt(a.Ip)).ToHashSet();
        var targets = new List<uint>();
        if (ctx.Ranges.Count > 0) targets.AddRange(ctx.Ranges.SelectMany(r => r.Addresses()));
        else
            foreach (var a in ctx.Adapters)
            foreach (var addr in a.Addresses)
            {
                var ip = Ip4.ToUInt(addr.Ip);
                if ((ip >> 16) == 0xA9FE) continue;
                // Ping is slower than ARP. With Npcap the ARP sweep already covers the whole LAN, so ping only
                // the /22 around this PC; without Npcap ping is all we have, so go up to /20 (4096 addresses).
                var cap = ctx.Engine.CaptureAvailable ? 22 : 20;
                targets.AddRange(Subnet.Of(ip, Math.Max(addr.Prefix, cap)).Hosts());
            }
        targets = targets.Distinct().Where(t => !own.Contains(t)).ToList();
        if (targets.Count == 0) return;

        // 1) ping everything not found yet
        var alive = new ConcurrentBag<uint>();
        var tcpAlive = new ConcurrentDictionary<uint, byte>();
        var todo = targets.Where(t => ctx.Store.FindByIp(Ip4.FromUInt(t)) == null).ToList();
        ctx.Log($"Ping sweep: {todo.Count} addresses not found by ARP");
        var done = 0;
        using (var sem = new SemaphoreSlim(256))
        {
            await Task.WhenAll(todo.Select(async t =>
            {
                await sem.WaitAsync(ct);
                try
                {
                    using var p = new Ping();
                    var r = await p.SendPingAsync(Ip4.FromUInt(t), 900);
                    if (r.Status == IPStatus.Success) alive.Add(t);
                }
                catch { }
                finally
                {
                    sem.Release();
                    var n = Interlocked.Increment(ref done);
                    if (n % 64 == 0) ctx.Status.Report($"Ping sweep: {n}/{todo.Count}");
                }
            }));
        }
        ct.ThrowIfCancellationRequested();

        // 2) TCP probe for routed addresses that ignored ping
        var routedSilent = todo.Where(t => !alive.Contains(t) && !IsLocal(ctx, t)).ToList();
        if (routedSilent.Count > 0 && routedSilent.Count <= 8192)
        {
            ctx.Log($"TCP probe: {routedSilent.Count} addresses that ignore ping");
            done = 0;
            using var sem = new SemaphoreSlim(512);
            await Task.WhenAll(routedSilent.Select(async t =>
            {
                await sem.WaitAsync(ct);
                try
                {
                    foreach (var port in AlivePorts)
                    {
                        var res = await TryConnect(Ip4.FromUInt(t), port, 500, ct);
                        if (res == ConnectResult.Open)
                        {
                            alive.Add(t); tcpAlive[t] = 0;
                            ctx.Store.ObserveIp(Ip4.FromUInt(t), "TCP", null, d => d.OpenPorts.Add(port));
                            break;
                        }
                        if (res == ConnectResult.Refused) { alive.Add(t); tcpAlive[t] = 0; break; }
                    }
                }
                finally
                {
                    sem.Release();
                    var n = Interlocked.Increment(ref done);
                    if (n % 32 == 0) ctx.Status.Report($"TCP probe: {n}/{routedSilent.Count}");
                }
            }));
        }

        // 3) MACs from the ARP table (also catches devices that answered ARP but blocked ping).
        //    Windows keeps entries of devices that are gone ("Stale"): those come back only when the device answered now.
        var targetSet = targets.ToHashSet();
        var old = 0;
        foreach (var e in ArpCache.ReadWithState())
        {
            var v = Ip4.ToUInt(e.Ip);
            if (!targetSet.Contains(v) || !DeviceStore.IsValidMac(e.Mac)) continue;
            if (!KeepArpEntry(e.Fresh, alive.Contains(v), ctx.Store.FindByIp(e.Ip) != null)) { old++; continue; }
            var adapter = ctx.Adapters.FirstOrDefault(a => a.OwnsSubnetOf(e.Ip));
            ctx.Store.Observe(e.Mac, alive.Contains(v) ? "Ping" : "ARP table", adapter, e.Ip);
        }
        if (old > 0) ctx.Log($"ARP table: skipped {old} old entr{(old == 1 ? "y" : "ies")} of Windows (those devices did not answer now)");
        // 4) the rest (routed, or no ARP entry): add by IP only
        foreach (var t in alive)
        {
            var ip = Ip4.FromUInt(t);
            var d = ctx.Store.FindByIp(ip);
            var how = tcpAlive.ContainsKey(t) ? "TCP" : "Ping";
            if (d == null) ctx.Store.ObserveIp(ip, how, ctx.Adapters.FirstOrDefault(a => a.OwnsSubnetOf(ip)));
            else ctx.Store.Touch(d, x => x.Sources.Add(how));
        }
        ctx.Log(alive.IsEmpty ? "Ping/TCP sweep: no extra devices (ARP already found every device that answers)" : $"Ping/TCP sweep: {alive.Count} more device(s) answered");
    }

    /// <summary>
    /// Is an ARP table entry worth listing? Yes when the device answered ping now, is already listed (found another
    /// way), or Windows heard from it in the last ~30 s. An old entry ("Stale") alone is a device that may be gone.
    /// </summary>
    public static bool KeepArpEntry(bool? fresh, bool answeredPing, bool alreadyListed) => answeredPing || alreadyListed || fresh != false;

    private static bool IsLocal(ScanContext ctx, uint ip) => ctx.Adapters.Any(a => a.Addresses.Any(x => x.Subnet.Contains(ip)));

    private enum ConnectResult { Open, Refused, NoAnswer }

    private static async Task<ConnectResult> TryConnect(IPAddress ip, int port, int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try { await s.ConnectAsync(ip, port, cts.Token); return ConnectResult.Open; }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused) { return ConnectResult.Refused; }
        catch { ct.ThrowIfCancellationRequested(); return ConnectResult.NoAnswer; }
    }
}
