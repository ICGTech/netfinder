using System.Collections.Concurrent;
using System.Net;
using NetFinder.Core.Net;

namespace NetFinder.Core.Model;

/// <summary>Thread-safe collection of all devices found so far (one entry per IP).</summary>
public sealed class DeviceStore
{
    private readonly ConcurrentDictionary<string, Device> _devices = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _lastKeyByMac = new(StringComparer.OrdinalIgnoreCase);
    private Func<IEnumerable<Adapter>> _adapters = () => Array.Empty<Adapter>();

    /// <summary>Raised (on a background thread) whenever a device is added or changed.</summary>
    public event Action<Device>? Changed;
    /// <summary>Raised when an entry is removed (merged into another one, or filtered as proxy ARP).</summary>
    public event Action<Device>? Removed;
    public event Action? Cleared;

    /// <summary>Device-type classifiers (set by the engine from the plugin registry).</summary>
    public List<Plugins.IDeviceClassifier> Classifiers { get; } = new();

    /// <summary>User-given names/types, applied when a device is first seen.</summary>
    public UserLabels Labels { get; set; } = new();

    /// <summary>Routers that answer ARP for whole foreign subnets ("proxy ARP"); their foreign answers are ignored.</summary>
    public ConcurrentDictionary<string, byte> ProxyArpMacs { get; } = new(StringComparer.OrdinalIgnoreCase);

    public void BindAdapters(Func<IEnumerable<Adapter>> adapters) => _adapters = adapters;

    public IReadOnlyCollection<Device> All => _devices.Values.ToList();
    public int Count => _devices.Count;

    public Device? Find(string key) => _devices.TryGetValue(key, out var d) ? d : null;
    public Device? FindByIp(IPAddress ip) => _devices.TryGetValue(ip.ToString(), out var d) ? d : null;

    /// <summary>Source MAC used for packets captured without Npcap (the MAC is unknown).</summary>
    public const string NoMac = "00:00:00:00:00:00";

    public static bool IsValidMac(string mac)
    {
        if (mac.Length != 17 || mac == "00:00:00:00:00:00") return false;
        try { return (Convert.ToByte(mac[..2], 16) & 1) == 0; } catch { return false; }
    }

    private bool IsLocal(IPAddress ip) => _adapters().Any(a => a.OwnsSubnetOf(ip));

    /// <summary>
    /// Record an observation of a device on the LAN. <paramref name="update"/> runs under the device lock.
    /// With an IP: updates (or creates) that IP's row. Without: updates the latest row of that MAC,
    /// or a MAC-only row until the IP is learned.
    /// </summary>
    public Device? Observe(string mac, string source, Adapter? adapter, IPAddress? ip = null, Action<Device>? update = null)
    {
        // Frames captured without Npcap (raw socket) carry no MAC: keep them as IP-only rows.
        if (mac == NoMac) return ip != null && Ip4.IsUsableHost(ip) ? ObserveIp(ip, source, adapter, update) : null;
        if (!IsValidMac(mac)) return null;
        mac = mac.ToUpperInvariant();
        Device dev;
        if (ip != null && Ip4.IsUsableHost(ip))
        {
            if (source == "ARP" && ProxyArpMacs.ContainsKey(mac) && !IsLocal(ip)) return null;
            var key = ip.ToString();
            dev = _devices.GetOrAdd(key, k => Create(k, mac, ip));
            lock (dev)
            {
                if (!dev.Mac.Equals(mac, StringComparison.OrdinalIgnoreCase))
                {
                    if (dev.Mac.Length > 0) dev.Info["Previous MAC"] = dev.Mac;
                    dev.Mac = mac;
                    dev.Vendor = OuiLookup.Lookup(mac);
                    dev.Routed = false;
                    Labels.Apply(dev);
                }
            }
            _lastKeyByMac[mac] = key;
            if (_devices.TryRemove("MAC " + mac, out var placeholder))
            {
                MergeInto(placeholder, dev);
                Removed?.Invoke(placeholder);
            }
        }
        else
        {
            if (_lastKeyByMac.TryGetValue(mac, out var k) && _devices.TryGetValue(k, out var existing) && existing.Mac == mac) dev = existing;
            else dev = _devices.GetOrAdd("MAC " + mac, kk => Create(kk, mac, null));
        }
        Apply(dev, source, adapter, update, mac);
        return dev;
    }

    /// <summary>A device that answered ping/TCP but whose MAC we cannot see (behind a router, or no Npcap).</summary>
    public Device ObserveIp(IPAddress ip, string source, Adapter? adapter, Action<Device>? update = null)
    {
        var dev = _devices.GetOrAdd(ip.ToString(), k => Create(k, "", ip));
        lock (dev) if (dev.Mac.Length == 0) dev.Routed = !IsLocal(ip);
        Apply(dev, source, adapter, update, null);
        return dev;
    }

    private Device Create(string key, string mac, IPAddress? ip)
    {
        var d = new Device(key, mac, ip) { Vendor = mac.Length > 0 ? OuiLookup.Lookup(mac) : null };
        Labels.Apply(d);
        return d;
    }

    private void Apply(Device dev, string source, Adapter? adapter, Action<Device>? update, string? mac)
    {
        lock (dev)
        {
            dev.LastSeen = DateTime.Now;
            dev.Sources.Add(source);
            if (adapter != null)
            {
                dev.AdapterId ??= adapter.Id;
                if (mac != null && adapter.Mac.Equals(mac, StringComparison.OrdinalIgnoreCase)) dev.IsSelf = true;
            }
            update?.Invoke(dev);
            UpdateReachability(dev);
            dev.Revision++;
        }
        Changed?.Invoke(dev);
    }

    private static void MergeInto(Device from, Device to)
    {
        lock (from) lock (to)
        {
            to.Hostname ??= from.Hostname;
            if (from.Model != null) to.OfferModel(from.Model, from.ModelSource ?? "", from.ModelRank);
            foreach (var s in from.Sources) to.Sources.Add(s);
            foreach (var kv in from.Info) to.Info.TryAdd(kv.Key, kv.Value);
            foreach (var s in from.Services) to.Services.Add(s);
            if (from.FirstSeen < to.FirstSeen) to.FirstSeen = from.FirstSeen;
            to.AdapterId ??= from.AdapterId;
        }
    }

    public void Touch(Device dev, Action<Device> update)
    {
        lock (dev) { update(dev); UpdateReachability(dev); dev.Revision++; }
        Changed?.Invoke(dev);
    }

    /// <summary>Recompute "same subnet as me" for every device (call after adapter IPs change).</summary>
    public void RecomputeReachability()
    {
        foreach (var d in _devices.Values) Touch(d, _ => { });
    }

    private void UpdateReachability(Device dev)
    {
        var ip = dev.Ip;
        var adapters = _adapters();
        var local = ip != null && adapters.Any(a => a.OwnsSubnetOf(ip));
        if (local) dev.Routed = false;
        dev.Reachable = ip != null && (local || dev.Routed);
        if (ip != null && adapters.Any(a => a.Gateways.Contains(ip))) dev.Info["Is my gateway"] = "yes";
        Classify(dev);
    }

    private void Classify(Device dev)
    {
        if (Classifiers.Count == 0) return;
        var scores = new Plugins.TypeScores();
        foreach (var c in Classifiers)
        {
            try { c.Score(dev, scores); } catch { }
        }
        var best = scores.Best;
        if (best is { } b && b.Score >= 20)
        {
            dev.Type = b.Type;
            dev.TypeReason = string.Join(", ", b.Why.Distinct().Take(4));
        }
        else { dev.Type = DeviceTypes.Unknown; dev.TypeReason = ""; }
    }

    /// <summary>
    /// A router doing "proxy ARP" answers our ARP probes for every address of a foreign subnet,
    /// which would create hundreds of fake rows with the router's MAC. Remove them.
    /// Returns (mac, count) for every MAC suppressed.
    /// </summary>
    public List<(string Mac, int Count)> SuppressProxyArp(int threshold = 8)
    {
        var result = new List<(string, int)>();
        var suspects = _devices.Values
            .Where(d => { lock (d) return d.Ip != null && d.Mac.Length > 0 && !IsLocal(d.Ip) && d.Sources.Count == 1 && d.Sources.Contains("ARP"); })
            .GroupBy(d => d.Mac)
            .Where(g => g.Count() > threshold);
        foreach (var g in suspects)
        {
            ProxyArpMacs[g.Key] = 0;
            foreach (var d in g)
                if (_devices.TryRemove(d.Key, out _)) Removed?.Invoke(d);
            result.Add((g.Key, g.Count()));
        }
        return result;
    }

    public void Remove(Device d)
    {
        if (_devices.TryRemove(d.Key, out _)) Removed?.Invoke(d);
    }

    public void Clear()
    {
        _devices.Clear();
        _lastKeyByMac.Clear();
        Cleared?.Invoke();
    }
}
