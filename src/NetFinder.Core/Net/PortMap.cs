using NetFinder.Core.Model;

namespace NetFinder.Core.Net;

/// <summary>
/// Which switch port each device is plugged into, from the MAC addresses the switches learned (read over SNMP).
/// A device seen on several switches is put on the port with the fewest devices behind it: that is its own port,
/// the others are the links between switches.
/// </summary>
public static class PortMap
{
    public const string PortKey = "Switch port";
    public const string ArpMacKey = "MAC (router's ARP table)";
    private static readonly object Gate = new();

    public sealed record Spot(Device Switch, string SwitchName, string SwitchIp, SwitchPort Port)
    {
        /// <summary>"CORE-SW1 · port Gi1/0/7", plus how many devices share the port when it is more than this one
        /// (another switch or a Wi-Fi access point is plugged in there).</summary>
        public string Text => $"{SwitchName} · port {Port.Name}" + (Port.Macs.Count > 1 ? $" ({Port.Macs.Count} devices)" : "");
    }

    /// <summary>The switches read so far: (device, name, IP, state). Takes each device's lock.</summary>
    public static List<(Device Device, string Name, string Ip, SwitchState State)> Switches(IEnumerable<Device> devices)
    {
        var list = new List<(Device, string, string, SwitchState)>();
        foreach (var d in devices)
            lock (d)
                if (d.Switch != null && d.Ip != null)
                {
                    var ip = d.Ip.ToString();
                    var name = d.CustomName ?? d.Hostname ?? d.Info.GetValueOrDefault("SNMP name") ?? ip;
                    list.Add((d, name.Split('.')[0], ip, d.Switch));
                }
        return list;
    }

    /// <summary>Where a MAC is plugged in, or null when no switch learned it.</summary>
    public static Spot? Locate(string mac, IReadOnlyList<(Device Device, string Name, string Ip, SwitchState State)> switches, Device? self = null)
    {
        Spot? best = null;
        foreach (var (dev, name, ip, st) in switches)
        {
            if (dev == self || !st.IsBridge) continue;
            foreach (var p in st.Ports)
                if (p.Macs.Contains(mac) && (best == null || p.Macs.Count < best.Port.Macs.Count))
                    best = new Spot(dev, name, ip, p);
        }
        return best;
    }

    /// <summary>
    /// Writes "Switch port" (and, for devices behind a router, the MAC from the router's ARP table) on every device,
    /// touching only the ones that changed. Returns how many changed.
    /// </summary>
    public static int Apply(DeviceStore store)
    {
        lock (Gate)
        {
            var all = store.All;
            var switches = Switches(all);
            if (switches.Count == 0) return 0;
            var arp = new Dictionary<string, string>();
            foreach (var s in switches) foreach (var kv in s.State.Arp) arp.TryAdd(kv.Key, kv.Value);
            var changed = 0;
            foreach (var d in all)
            {
                string mac, ip; string? oldPort, oldArp;
                lock (d)
                {
                    ip = d.Ip?.ToString() ?? "";
                    mac = d.Mac;
                    oldPort = d.Info.GetValueOrDefault(PortKey);
                    oldArp = d.Info.GetValueOrDefault(ArpMacKey);
                }
                var arpMac = mac.Length == 0 && arp.TryGetValue(ip, out var am) ? am : null;
                var spot = (mac.Length > 0 ? mac : arpMac) is { } m ? Locate(m, switches, d) : null;
                var port = spot?.Text;
                if (port == oldPort && arpMac == oldArp) continue;
                store.Touch(d, x =>
                {
                    if (port != null) x.Info[PortKey] = port; else x.Info.Remove(PortKey);
                    if (arpMac != null) x.Info[ArpMacKey] = arpMac; else x.Info.Remove(ArpMacKey);
                });
                changed++;
            }
            return changed;
        }
    }
}
