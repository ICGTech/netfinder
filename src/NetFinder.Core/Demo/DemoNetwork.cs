using System.Net;
using NetFinder.Core.Model;

namespace NetFinder.Core.Demo;

/// <summary>
/// Sample devices for screenshots and UI testing (NETFINDER_DEMO=1): a made-up office on 10.0.0.0/16,
/// so the pictures look the same on any PC and show no real network.
/// </summary>
public static class DemoNetwork
{
    public static Adapter Adapter()
    {
        var a = new Adapter
        {
            Id = "{00000000-DE70-0000-0000-000000000001}", PcapName = "demo", FriendlyName = "Ethernet",
            Description = "Intel(R) Ethernet Connection I219-LM", IsUp = true, MacBytes = new byte[] { 0x9C, 0xB6, 0x54, 0x10, 0x20, 0x30 },
        };
        a.Addresses.Add(new AdapterAddress(IPAddress.Parse("10.0.0.20"), 16));
        a.Gateways.Add(IPAddress.Parse("10.0.0.15"));
        return a;
    }

    public static void Fill(NetworkEngine e)
    {
        var a = e.Adapters.FirstOrDefault();
        var now = DateTime.Now;
        void Add(string mac, string ip, string via, Action<Device> u) => e.Store.Observe(mac, via, a, IPAddress.Parse(ip), d =>
        {
            d.PortsCheckedAt = now;
            u(d);
        });
        void Ports(Device d, params int[] p) { foreach (var x in p) d.OpenPorts.Add(x); }
        void Windows(Device d, string model, string? maker, string win, string via = "Remote Registry")
        {
            d.OfferModel(model, $"Windows ({via})", 100);
            if (maker != null) d.Info["Manufacturer"] = maker;
            d.Info["Windows"] = win;
            d.Info["Workgroup / domain"] = "OFFICE";
            d.Sources.Add(via);
        }

        if (a != null) Add(a.Mac, "10.0.0.20", "ARP", d => { d.Hostname = "it-desk01"; Windows(d, "HP EliteDesk 800 G4 SFF", "HP", "Windows 11 Pro 23H2", "WMI"); });
        Add("50:C7:BF:3A:10:15", "10.0.0.15", "ARP", d =>
        {
            d.Hostname = "TL-WR820N"; d.OfferModel("TL-WR820N 2.0", "UPnP", 75); d.Info["DHCP server"] = "yes"; Ports(d, 53, 80);
        });
        Add("3C:52:82:AA:BB:02", "10.0.0.2", "LLDP", d => { d.Hostname = "CORE-SW1"; d.OfferModel("Aruba 2930F-48G Switch", "LLDP", 40); d.Info["Connected to its port"] = "1/1/7"; Ports(d, 22, 80, 443); });
        Add("00:50:56:9A:01:03", "10.0.0.3", "NetBIOS", d => { d.Hostname = "new-fileserver"; Windows(d, "VMware Virtual Platform", "VMware, Inc.", "Windows Server 2019 Standard", "WMI"); Ports(d, 135, 139, 445, 3389); });
        Add("00:90:A9:44:55:07", "10.0.0.7", "mDNS", d => { d.Hostname = "WDMYCLOUDEX4100"; d.OfferModel("WDMyCloudEX4100", "UPnP", 75); d.Services.Add("_smb._tcp"); Ports(d, 80, 443, 445); });
        Add("00:50:56:9A:01:12", "10.0.0.12", "NetBIOS", d => { d.Hostname = "bio-server"; Windows(d, "VMware Virtual Platform", "VMware, Inc.", "Windows Server 2016 Standard", "WMI"); Ports(d, 80, 135, 445); });
        Add("9C:B6:54:1A:2F:43", "10.0.0.43", "NetBIOS", d => { d.Hostname = "madapc0165"; Windows(d, "HP ProDesk 600 G3 MT", "HP", "Windows 10 Pro 22H2"); Ports(d, 135, 139, 445); });
        Add("9C:B6:54:1A:2F:80", "10.0.0.45", "NetBIOS", d =>
        {
            d.Hostname = "acc-pc07.office.local";
            Windows(d, "HP ProDesk 600 G3 MT", "HP", "Windows 10 Pro 22H2");
            d.Info["Serial number"] = "CZC7451KQ8";
            d.Info["Computer name"] = "ACC-PC07";
            d.Info["CPU"] = "Intel Core i5-7500 @ 3.40GHz";
            d.Info["RAM"] = "8 GB";
            d.Info["Disk"] = "SAMSUNG MZ7LN256HAJQ (SSD, 256 GB)  +  ST1000DM010-2EP102 (HDD, 1 TB)";
            d.Info["Drives"] = "C: 238 GB (112 GB free)  +  D: 932 GB (610 GB free)";
            d.Info["Graphics"] = "Intel HD Graphics 630 (1 GB)";
            d.Info["Logged-in user"] = "OFFICE\\accounts2";
            Ports(d, 135, 139, 445);
        });
        Add("D4:BE:D9:3C:11:06", "10.0.0.6", "ARP", d => { d.Info["Windows status"] = "Firewall blocks it"; });
        Add("9C:B6:54:1A:30:AE", "10.0.0.174", "NetBIOS", d => { d.Hostname = "eng-ws02"; Windows(d, "HP Z800 Workstation", "HP", "Windows 10 Pro 22H2"); Ports(d, 135, 139, 445, 3389); });
        Add("00:22:F3:5C:20:C9", "10.0.0.201", "mDNS", d => { d.OfferModel("SHARP MX-3114N", "IPP", 85); d.Services.Add("_ipp._tcp"); d.Services.Add("_printer._tcp"); Ports(d, 80, 443, 631, 9100); });
        Add("C0:56:E3:71:22:40", "10.0.0.64", "SSDP", d =>
        {
            d.OfferModel("DS-7608NI-K2/8P", "UPnP", 75); d.Info["UPnP server"] = "Linux/3.10 UPnP/1.0 Hikvision"; d.Info["NVR cameras"] = "8"; Ports(d, 80, 554, 8000);
        });
        Add("A8:23:FE:10:20:33", "10.0.0.51", "SSDP", d => { d.Hostname = "LGwebOSTV"; d.Info["UPnP server"] = "WebOS/4.1.0 UPnP/1.0"; d.Services.Add("_googlecast._tcp"); Ports(d, 3000, 8008); });
        Add("64:A2:F9:01:02:58", "10.0.0.88", "DHCP", d => { d.Hostname = "OnePlus-11"; d.Info["DHCP vendor class"] = "android-dhcp-14"; });
        Add("C0:56:E3:11:22:33", "192.168.1.64", "ARP", d => { d.Info["UPnP server"] = "Linux/3.10 UPnP/1.0 Hikvision"; d.PortsCheckedAt = null; });

        e.Log("Found 15 devices on Ethernet (10.0.0.0/16) and 1 on another subnet (192.168.1.0/24)");
        e.Log("Windows 10.0.0.45 (HP): login accepted (OFFICE\\administrator)");
        e.Log("Windows 10.0.0.45 (HP): HP ProDesk 600 G3 MT (via Remote Registry, login OFFICE\\administrator)");
        e.Log("Windows 10.0.0.45 (HP): CPU Intel Core i5-7500 @ 3.40GHz  ·  RAM 8 GB  ·  Disk 1: SAMSUNG MZ7LN256HAJQ (SSD, 256 GB)  ·  Disk 2: ST1000DM010-2EP102 (HDD, 1 TB)");
        e.Log("Windows 10.0.0.45 (HP): RemoteRegistry put back to disabled");
        e.Log("Windows 10.0.0.6 (Dell): port 135 answers but the firewall blocks WMI");
    }
}
