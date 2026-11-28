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

    /// <summary>Devices "watched" in demo mode: the printer is down, the others answer.</summary>
    public static List<WatchItem> Watched() => new[] { "10.0.0.2", "10.0.0.3", "10.0.0.12", "10.0.0.64", "10.0.0.201" }
        .Select(ip => new WatchItem { Ip = ip }).ToList();

    public static Task<Monitoring.ProbeResult> WatchProbe(IPAddress ip, CancellationToken ct) => Task.FromResult(ip.ToString() switch
    {
        "10.0.0.201" => new Monitoring.ProbeResult(false, null, ""),
        "10.0.0.3" => new Monitoring.ProbeResult(true, 1, "ping"),
        "10.0.0.12" => new Monitoring.ProbeResult(true, 2, "port 445"),
        _ => new Monitoring.ProbeResult(true, 3, "ping"),
    });

    private static void Printer(Device d, long pages, string status, string[] alerts, params PrinterSupply[] supplies)
    {
        d.Printer = new PrinterState(supplies, pages, status, alerts, DateTime.Now);
        d.Sources.Add("SNMP");
        d.SnmpTriedAt = DateTime.Now;
        d.Info["Pages printed"] = pages.ToString("N0", System.Globalization.CultureInfo.InvariantCulture);
        d.Info["Printer status"] = status;
        d.Info["Ink / toner"] = string.Join(" · ", supplies.Select(x => x.Text));
    }

    /// <summary>A 48-port switch with 4 uplink slots: who is on which port (the MACs of the demo devices).</summary>
    private static SwitchState DemoSwitch(string? myMac)
    {
        var on = new Dictionary<int, string[]>
        {
            [1] = new[] { "50:C7:BF:3A:10:15" },
            [3] = new[] { "00:50:56:9A:01:03", "00:50:56:9A:01:12", "00:25:B5:00:00:1F" },
            [5] = new[] { "F8:BC:12:4D:00:0A" }, [7] = new[] { "00:90:A9:44:55:07" },
            [12] = new[] { myMac ?? "9C:B6:54:10:20:30" }, [14] = new[] { "9C:B6:54:1A:2F:43" }, [15] = new[] { "9C:B6:54:1A:2F:80" },
            [16] = new[] { "D4:BE:D9:3C:11:06" }, [20] = new[] { "9C:B6:54:1A:30:AE" }, [24] = new[] { "00:22:F3:5C:20:C9" }, [25] = new[] { "A0:8C:FD:12:34:30" },
            [30] = new[] { "C0:56:E3:71:22:40" }, [33] = new[] { "AC:84:C6:11:22:33", "A8:23:FE:10:20:33", "64:A2:F9:01:02:58" },
        };
        var alias = new Dictionary<int, string> { [1] = "Router", [3] = "ESXi host", [24] = "Copier 2nd floor", [30] = "NVR", [33] = "AP reception", [49] = "Uplink to SW2" };
        var ports = new List<SwitchPort>();
        for (var i = 1; i <= 52; i++)
        {
            var macs = on.TryGetValue(i, out var m) ? m : Array.Empty<string>();
            var up = macs.Length > 0 || i is 40 or 49;
            ports.Add(new SwitchPort(i, i.ToString(), alias.GetValueOrDefault(i), up, i is 47 or 48, up ? (i >= 49 ? 10_000 : i == 25 ? 100 : 1000) : 0,
                macs, macs.Length > 0 ? new[] { i == 33 ? 20 : 1 } : Array.Empty<int>()));
        }
        return new SwitchState(ports, new Dictionary<string, string>(), true, DateTime.Now);
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
            d.SnmpTriedAt = now; // asked, no answer: its panel shows the box for another SNMP community
        });
        Add("3C:52:82:AA:BB:02", "10.0.0.2", "LLDP", d =>
        {
            d.Hostname = "CORE-SW1"; d.OfferModel("Aruba 2930F-48G Switch", "LLDP", 40); d.Info["Connected to its port"] = "1/1/7"; Ports(d, 22, 23, 80, 443);
            d.Switch = DemoSwitch(a?.Mac);
            d.Sources.Add("SNMP"); d.SnmpTriedAt = now;
            d.Info["Switch ports"] = $"{d.Switch.Up} of {d.Switch.Ports.Count} up · {d.Switch.MacCount} MAC addresses learned";
        });
        Add("00:50:56:9A:01:03", "10.0.0.3", "NetBIOS", d => { d.Hostname = "new-fileserver"; Windows(d, "VMware Virtual Platform", "VMware, Inc.", "Windows Server 2019 Standard", "WMI"); Ports(d, 135, 139, 445, 3389); });
        // a domain controller nobody logged in to: known as a server only by its ports (Kerberos, LDAP, DNS)
        Add("F8:BC:12:4D:00:0A", "10.0.0.10", "NetBIOS", d => { d.Hostname = "OFFICE-DC1"; d.Info["Workgroup / domain"] = "OFFICE"; Ports(d, 53, 88, 135, 139, 389, 445, 3268, 3389); });
        Add("00:90:A9:44:55:07", "10.0.0.7", "mDNS", d => { d.Hostname = "WDMYCLOUDEX4100"; d.OfferModel("WDMyCloudEX4100", "UPnP", 75); d.Services.Add("_smb._tcp"); Ports(d, 21, 80, 443, 445); });
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
        Add("00:22:F3:5C:20:C9", "10.0.0.201", "mDNS", d =>
        {
            d.OfferModel("SHARP MX-3114N", "IPP", 85); d.Services.Add("_ipp._tcp"); d.Services.Add("_printer._tcp"); Ports(d, 80, 443, 631, 9100);
            Printer(d, 48213, "Ready", new[] { "Toner low" },
                new PrinterSupply("Black toner", "black", 62, "OK", false, true) { Detail = "MX-36GTBA" },
                new PrinterSupply("Cyan toner", "cyan", 18, "OK", false, true) { Detail = "MX-36GTCA" },
                new PrinterSupply("Magenta toner", "magenta", 7, "Low", false, true) { Detail = "MX-36GTMA" },
                new PrinterSupply("Yellow toner", "yellow", 74, "OK", false, true) { Detail = "MX-36GTYA" },
                new PrinterSupply("Waste toner box", null, 35, "OK", true, false),
                new PrinterSupply("Drum", null, null, "OK", false, false));
        });
        Add("A0:8C:FD:12:34:30", "10.0.0.30", "mDNS", d =>
        {
            d.Hostname = "NPI1A2B3C"; d.OfferModel("HP LaserJet Pro M404dn", "SNMP printer", 80); d.Services.Add("_ipp._tcp"); Ports(d, 80, 443, 631, 9100);
            Printer(d, 12840, "Ready", Array.Empty<string>(), new PrinterSupply("Black toner", "black", 23, "OK", false, true) { Detail = "Black Cartridge HP CF259A" });
        });
        Add("C0:56:E3:71:22:40", "10.0.0.64", "SSDP", d =>
        {
            d.OfferModel("DS-7608NI-K2/8P", "UPnP", 75); d.Info["UPnP server"] = "Linux/3.10 UPnP/1.0 Hikvision"; d.Info["NVR cameras"] = "8"; Ports(d, 80, 554, 8000);
        });
        Add("A8:23:FE:10:20:33", "10.0.0.51", "SSDP", d => { d.Hostname = "LGwebOSTV"; d.Info["UPnP server"] = "WebOS/4.1.0 UPnP/1.0"; d.Services.Add("_googlecast._tcp"); Ports(d, 3000, 8008); });
        Add("64:A2:F9:01:02:58", "10.0.0.88", "DHCP", d => { d.Hostname = "OnePlus-11"; d.Info["DHCP vendor class"] = "android-dhcp-14"; });
        Add("C0:56:E3:11:22:33", "192.168.1.64", "ARP", d => { d.Info["UPnP server"] = "Linux/3.10 UPnP/1.0 Hikvision"; d.PortsCheckedAt = null; });

        Net.PortMap.Apply(e.Store);

        e.Log("Found 17 devices on Ethernet (10.0.0.0/16) and 1 on another subnet (192.168.1.0/24)");
        e.Log("SNMP 10.0.0.201: printer Black toner 62%, Cyan toner 18%, Magenta toner 7%, Yellow toner 74%, 48,213 pages, Ready");
        e.Log("SNMP 10.0.0.2: switch, 17 of 52 ports up, 19 MAC addresses learned");
        e.Log("Windows 10.0.0.45 (HP): login accepted (OFFICE\\administrator)");
        e.Log("Windows 10.0.0.45 (HP): HP ProDesk 600 G3 MT (via Remote Registry, login OFFICE\\administrator)");
        e.Log("Windows 10.0.0.45 (HP): CPU Intel Core i5-7500 @ 3.40GHz  ·  RAM 8 GB  ·  Disk 1: SAMSUNG MZ7LN256HAJQ (SSD, 256 GB)  ·  Disk 2: ST1000DM010-2EP102 (HDD, 1 TB)");
        e.Log("Windows 10.0.0.45 (HP): RemoteRegistry put back to disabled");
        e.Log("Windows 10.0.0.6 (Dell): port 135 answers but the firewall blocks WMI");
    }
}
