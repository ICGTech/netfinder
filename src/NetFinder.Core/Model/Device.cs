using System.Net;

namespace NetFinder.Core.Model;

/// <summary>
/// One row in the list: one IP address (like Advanced IP Scanner). Several IPs that share one MAC
/// (range extenders, Access Points in MAC-NAT mode, servers with several IPs) are separate rows.
/// A device whose IP is not known yet (e.g. only seen in LLDP or a DHCP DISCOVER) is keyed by its MAC
/// until an IP shows up. Lock on the device before reading/writing.
/// </summary>
public sealed class Device
{
    public Device(string key, string mac, IPAddress? ip)
    {
        Key = key;
        Mac = mac;
        if (ip != null) Ips.Add(ip);
    }

    /// <summary>"10.10.20.5" for IP rows, "MAC AA:BB:…" while the IP is unknown.</summary>
    public string Key { get; }

    /// <summary>MAC address, or "" when the device is behind a router (MAC not visible).</summary>
    public string Mac { get; set; }

    /// <summary>Found through a router (answered ping/TCP but is not on this PC's LAN).</summary>
    public bool Routed { get; set; }

    /// <summary>Key used to remember the user's name/type for this device.</summary>
    public string LabelKey => Mac.Length > 0 ? Mac : "IP " + Ip;
    public string? Vendor { get; set; }
    public string? Hostname { get; set; }
    public string? Model { get; set; }

    /// <summary>Detected type: "Android phone", "Printer", "Switch"... (see DeviceTypes).</summary>
    public string Type { get; set; } = DeviceTypes.Unknown;
    public string TypeReason { get; set; } = "";
    /// <summary>Set by the user (right-click → Set type). Wins over detection.</summary>
    public string? TypeOverride { get; set; }
    /// <summary>Name given by the user. Wins over detected hostname.</summary>
    public string? CustomName { get; set; }
    public string? Notes { get; set; }
    public string EffectiveType => TypeOverride ?? Type;

    /// <summary>All IPv4 addresses seen for this MAC, most recent first.</summary>
    public List<IPAddress> Ips { get; } = new();
    public IPAddress? Ip => Ips.Count > 0 ? Ips[0] : null;

    /// <summary>How we found it: ARP, DHCP, mDNS, SSDP, NetBIOS, LLDP, CDP, Scan...</summary>
    public SortedSet<string> Sources { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Free-form facts ("DHCP requested IP", "SSDP server", "LLDP port"...).</summary>
    public SortedDictionary<string, string> Info { get; } = new(StringComparer.OrdinalIgnoreCase);

    public SortedSet<int> OpenPorts { get; } = new();
    /// <summary>Extra per-port info, e.g. the web page title.</summary>
    public Dictionary<int, string> PortInfo { get; } = new();
    public DateTime? PortsCheckedAt { get; set; }

    /// <summary>mDNS / DNS-SD service types announced by the device (e.g. _http._tcp).</summary>
    public SortedSet<string> Services { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Id of the network adapter it was seen on.</summary>
    public string? AdapterId { get; set; }
    public DateTime FirstSeen { get; set; } = DateTime.Now;
    public DateTime LastSeen { get; set; } = DateTime.Now;

    /// <summary>True when the device IP is inside one of this PC's own subnets (we can talk to it directly).</summary>
    public bool Reachable { get; set; }
    public bool IsSelf { get; set; }

    /// <summary>Bump on every change; the UI uses it to know what to repaint.</summary>
    public int Revision { get; set; }

    public bool AddIp(IPAddress ip)
    {
        if (!Net.Ip4.IsUsableHost(ip)) return false;
        var i = Ips.IndexOf(ip);
        if (i == 0) return false;
        if (i > 0) Ips.RemoveAt(i);
        Ips.Insert(0, ip);
        if (Ips.Count > 8) Ips.RemoveAt(Ips.Count - 1);
        return true;
    }

    public string DisplayName => CustomName ?? Hostname ?? Model ?? "";
}
