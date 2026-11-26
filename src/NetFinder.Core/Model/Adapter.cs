using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetFinder.Core.Net;

namespace NetFinder.Core.Model;

public sealed record AdapterAddress(IPAddress Ip, int Prefix)
{
    public Subnet Subnet => Subnet.Of(Ip, Prefix);
    public override string ToString() => $"{Ip}/{Prefix}";
}

/// <summary>A local network card (Ethernet / Wi-Fi) that we can capture and send on.</summary>
public sealed class Adapter
{
    public required string Id { get; init; }            // Windows interface GUID
    public required string PcapName { get; init; }      // \Device\NPF_{GUID}
    public string FriendlyName { get; set; } = "";      // "Ethernet", "Wi-Fi"
    public string Description { get; set; } = "";
    public byte[] MacBytes { get; set; } = new byte[6];
    public string Mac => Net.Mac.Format(MacBytes);
    public int InterfaceIndex { get; set; }
    public bool IsUp { get; set; }
    public List<AdapterAddress> Addresses { get; } = new();
    public List<IPAddress> Gateways { get; } = new();

    /// <summary>The pcap device, kept as object so the model has no hard dependency on SharpPcap.</summary>
    public object? PcapDevice { get; set; }

    /// <summary>
    /// A host-only virtual network of Hyper-V, VMware, VirtualBox, WSL or Docker on this PC (no gateway): only this PC's own
    /// virtual machines live there, so "All connected adapters" skips it. A Hyper-V external switch (with a gateway) is the real LAN and stays.
    /// </summary>
    public bool IsHostOnlyVirtual =>
        Gateways.Count == 0 && System.Text.RegularExpressions.Regex.IsMatch(Description + " | " + FriendlyName,
            @"hyper-v virtual ethernet|vmware virtual ethernet|virtualbox host-only|vethernet|\bvmnet\d|docker|\bwsl\b|default switch|loopback",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    public bool OwnsSubnetOf(IPAddress ip) => Addresses.Any(a => a.Subnet.Contains(ip));
    public AdapterAddress? AddressFor(IPAddress ip) => Addresses.FirstOrDefault(a => a.Subnet.Contains(ip));
    public uint PrimaryIp => Addresses.Count > 0 ? Ip4.ToUInt(Addresses[0].Ip) : 0;

    /// <summary>Re-read IPs / gateways from Windows (e.g. after adding a temporary IP).</summary>
    public void RefreshFromOs()
    {
        var ni = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => string.Equals(n.Id.Trim('{', '}'), Id.Trim('{', '}'), StringComparison.OrdinalIgnoreCase));
        if (ni == null) return;
        FriendlyName = ni.Name;
        Description = ni.Description;
        IsUp = ni.OperationalStatus == OperationalStatus.Up;
        var mac = ni.GetPhysicalAddress().GetAddressBytes();
        if (mac.Length == 6) MacBytes = mac;
        var props = ni.GetIPProperties();
        try { InterfaceIndex = props.GetIPv4Properties()?.Index ?? 0; } catch { }
        Addresses.Clear();
        foreach (var u in props.UnicastAddresses)
            if (u.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(u.Address))
                Addresses.Add(new AdapterAddress(u.Address, u.PrefixLength));
        Gateways.Clear();
        foreach (var g in props.GatewayAddresses)
            if (g.Address.AddressFamily == AddressFamily.InterNetwork) Gateways.Add(g.Address);
    }

    public override string ToString()
    {
        var ips = Addresses.Count == 0 ? "no IP" : string.Join(", ", Addresses);
        return $"{FriendlyName}  ({ips})";
    }
}
