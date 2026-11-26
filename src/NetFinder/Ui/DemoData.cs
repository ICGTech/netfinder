using System.Net;
using NetFinder.Core;

namespace NetFinder.Ui;

/// <summary>Sample devices for screenshots / UI testing. Enabled with the environment variable NETFINDER_DEMO=1.</summary>
internal static class DemoData
{
    public static void Fill(NetworkEngine e)
    {
        var a = e.Adapters.FirstOrDefault();
        void Add(string mac, string ip, string via, Action<Core.Model.Device>? u = null) =>
            e.Store.Observe(mac, via, a, IPAddress.Parse(ip), u);
        Add("C0:56:E3:11:22:33", "192.168.1.64", "ARP", d => { d.OpenPorts.Add(80); d.OpenPorts.Add(554); d.OpenPorts.Add(8000); d.Info["UPnP server"] = "Linux/3.10 UPnP/1.0 Hikvision"; });
        Add("3C:52:82:AA:BB:CC", "172.31.5.2", "LLDP", d => { d.Hostname = "CORE-SW1"; d.Model = "Aruba 2930F-48G Switch"; d.Info["Connected to its port"] = "Gi1/0/7"; });
        Add("A4:BB:6D:11:22:33", "10.10.20.15", "NetBIOS", d => { d.Hostname = "DESKTOP-AMR"; d.PortsCheckedAt = DateTime.Now; d.OpenPorts.Add(445); d.OpenPorts.Add(3389); });
        Add("00:80:77:44:55:66", "10.10.20.30", "mDNS", d => { d.Hostname = "BRN008077445566"; d.Model = "Brother MFC-L2710DW"; d.Services.Add("_ipp._tcp"); d.PortsCheckedAt = DateTime.Now; d.OpenPorts.Add(80); d.OpenPorts.Add(9100); });
        Add("64:A2:F9:01:02:03", "10.10.20.44", "DHCP", d => { d.Hostname = "Galaxy-A54"; d.Info["DHCP vendor class"] = "android-dhcp-14"; });
        Add("A8:23:FE:10:20:30", "10.10.20.51", "SSDP", d => { d.Hostname = "LGwebOSTV"; d.Info["UPnP server"] = "WebOS/4.1.0 UPnP/1.0"; d.Services.Add("_googlecast._tcp"); });
        Add("E4:8D:8C:AA:00:01", "10.10.20.1", "ARP", d => { d.Info["DHCP server"] = "yes"; d.Model = "RouterOS RB4011"; d.PortsCheckedAt = DateTime.Now; d.OpenPorts.Add(80); d.OpenPorts.Add(8291); d.OpenPorts.Add(53); });
        Add("F0:18:98:12:34:56", "10.10.20.60", "mDNS", d => { d.Hostname = "Amrs-iPhone"; });
        Add("00:11:32:0A:0B:0C", "192.168.0.10", "ARP", d => { d.Hostname = "DiskStation"; });
    }
}
