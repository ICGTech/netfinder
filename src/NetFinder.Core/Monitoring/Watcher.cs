using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetFinder.Core.Monitoring;

public enum Health { Unknown, Up, Down }

/// <summary>What "Watch devices" knows about one watched address. Lock on it before reading.</summary>
public sealed class WatchState
{
    public WatchState(string ip) => Ip = ip;
    public string Ip { get; }
    public Health Health { get; internal set; }
    /// <summary>When it went up or down (or when watching started).</summary>
    public DateTime Since { get; internal set; } = DateTime.Now;
    public DateTime? LastCheck { get; internal set; }
    /// <summary>Reply time of the last good check, in milliseconds.</summary>
    public long? Ms { get; internal set; }
    /// <summary>"ping", or "port 445" for devices that never answer ping.</summary>
    public string Via { get; internal set; } = "";
}

public readonly record struct ProbeResult(bool Up, long? Ms, string Via);

/// <summary>
/// Pings the watched devices every <see cref="Interval"/> and says when one stops answering or comes back.
/// The load on the network is tiny: one 32-byte ping per device per round. Only when a ping is not answered,
/// it tries again (up to <see cref="Tries"/> times, 1.5 s apart) before calling the device down, and a device
/// that never answers ping (Windows firewall) is checked with one TCP connection to a port it has open.
/// </summary>
public sealed class Watcher : IDisposable
{
    public delegate Task<ProbeResult> Prober(IPAddress ip, CancellationToken ct);

    private readonly Prober _probe;
    private readonly Func<IPAddress, IReadOnlyCollection<int>>? _openPorts;
    private readonly ConcurrentDictionary<string, WatchState> _states = new();
    private readonly object _gate = new();
    private CancellationTokenSource? _run;
    private CancellationTokenSource _wake = new();
    private TimeSpan _interval = TimeSpan.FromMinutes(1);

    /// <param name="probe">How one device is checked (tests pass a fake one).</param>
    /// <param name="openPorts">Ports known to be open on a device, for devices that ignore ping.</param>
    public Watcher(Prober? probe = null, Func<IPAddress, IReadOnlyCollection<int>>? openPorts = null)
    {
        _openPorts = openPorts;
        _probe = probe ?? PingOrPortAsync;
    }

    /// <summary>Misses in a row before a device counts as down.</summary>
    public int Tries { get; init; } = 3;
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(1.5);
    public int MaxParallel { get; init; } = 16;

    public TimeSpan Interval
    {
        get => _interval;
        set { _interval = value < TimeSpan.FromSeconds(5) ? TimeSpan.FromSeconds(5) : value; Wake(); }
    }

    /// <summary>A device went up or down (state, health before). Raised on a background thread.</summary>
    public event Action<WatchState, Health>? Changed;
    /// <summary>A round of checks finished. Raised on a background thread.</summary>
    public event Action? Checked;

    public bool Running => _run != null;
    public IReadOnlyList<WatchState> States => _states.Values.OrderBy(s => s.Ip).ToList();
    public WatchState? Get(string? ip) => ip != null && _states.TryGetValue(ip, out var s) ? s : null;
    public int Count => _states.Count;

    /// <summary>Sets the addresses to watch. Ones already watched keep their state; new ones are checked right away.</summary>
    public void SetTargets(IEnumerable<string> ips)
    {
        var want = ips.Where(i => IPAddress.TryParse(i, out _)).ToHashSet();
        foreach (var k in _states.Keys) if (!want.Contains(k)) _states.TryRemove(k, out _);
        var added = false;
        foreach (var ip in want) added |= _states.TryAdd(ip, new WatchState(ip));
        if (added) Wake();
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_run != null) return;
            _run = new CancellationTokenSource();
            var ct = _run.Token;
            _ = Task.Run(() => LoopAsync(ct));
        }
    }

    public void Stop()
    {
        lock (_gate)
        {
            _run?.Cancel();
            _run?.Dispose();
            _run = null;
        }
    }

    /// <summary>Checks now instead of waiting for the next round.</summary>
    public void Wake()
    {
        lock (_gate) _wake.Cancel();
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var started = Stopwatch.StartNew();
            try { await CheckAllAsync(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch { }
            CancellationToken wake;
            var again = false;
            lock (_gate)
            {
                // woken during the round (new devices, new interval): go again right away
                if (_wake.IsCancellationRequested) { _wake.Dispose(); _wake = new CancellationTokenSource(); again = true; }
                wake = _wake.Token;
            }
            if (again) continue;
            var wait = _interval - started.Elapsed;
            if (wait < TimeSpan.FromSeconds(1)) wait = TimeSpan.FromSeconds(1);
            using var both = CancellationTokenSource.CreateLinkedTokenSource(ct, wake);
            try { await Task.Delay(wait, both.Token); }
            catch (OperationCanceledException) { if (ct.IsCancellationRequested) return; }
        }
    }

    /// <summary>One round: every watched device once.</summary>
    public async Task CheckAllAsync(CancellationToken ct)
    {
        using var sem = new SemaphoreSlim(MaxParallel);
        await Task.WhenAll(_states.Values.ToList().Select(async s =>
        {
            await sem.WaitAsync(ct);
            try { await CheckOneAsync(s, ct); }
            finally { sem.Release(); }
        }));
        Checked?.Invoke();
    }

    private async Task CheckOneAsync(WatchState s, CancellationToken ct)
    {
        if (!IPAddress.TryParse(s.Ip, out var ip)) return;
        var r = default(ProbeResult);
        for (var i = 0; i < Math.Max(1, Tries); i++)
        {
            if (i > 0) await Task.Delay(RetryDelay, ct);
            try { r = await _probe(ip, ct); }
            catch (OperationCanceledException) { throw; }
            catch { r = default; }
            if (r.Up) break;
        }
        if (!_states.TryGetValue(s.Ip, out var cur) || cur != s) return; // stopped watching it meanwhile
        Health old, now = r.Up ? Health.Up : Health.Down;
        lock (s)
        {
            old = s.Health;
            s.LastCheck = DateTime.Now;
            if (r.Up) { s.Ms = r.Ms; s.Via = r.Via; }
            if (now != old) { s.Health = now; s.Since = DateTime.Now; }
        }
        if (now != old) Changed?.Invoke(s, old);
    }

    /// <summary>Ping first; a device that does not answer ping is tried on one or two ports it has open ("refused" also means it is on).</summary>
    private async Task<ProbeResult> PingOrPortAsync(IPAddress ip, CancellationToken ct)
    {
        try
        {
            using var p = new Ping();
            var reply = await p.SendPingAsync(ip, TimeSpan.FromMilliseconds(1000), new byte[32], null, ct);
            if (reply.Status == IPStatus.Success) return new ProbeResult(true, reply.RoundtripTime, "ping");
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        foreach (var port in (_openPorts?.Invoke(ip) ?? Array.Empty<int>()).Take(2))
        {
            var sw = Stopwatch.StartNew();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(1000);
            using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await sock.ConnectAsync(ip, port, cts.Token);
                return new ProbeResult(true, sw.ElapsedMilliseconds, $"port {port}");
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                return new ProbeResult(true, sw.ElapsedMilliseconds, $"port {port}");
            }
            catch { ct.ThrowIfCancellationRequested(); }
        }
        return new ProbeResult(false, null, "");
    }

    public void Dispose()
    {
        Stop();
        lock (_gate) _wake.Dispose();
    }
}
