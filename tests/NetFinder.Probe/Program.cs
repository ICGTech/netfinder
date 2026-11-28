// Console harness used to test the engine on Linux/Windows without the GUI.
// usage: NetFinder.Probe <interface> [listenSeconds] [scan] [ports]
using NetFinder.Core;
using NetFinder.Core.Model;

// NVR mode: NetFinder.Probe nvr <url> <user> <pass> [hik|dahua]
if (args.Length >= 4 && args[0] == "nvr")
{
    var brand = args.Length > 4 ? (args[4] == "dahua" ? NetFinder.Core.Nvr.NvrBrand.Dahua : NetFinder.Core.Nvr.NvrBrand.Hikvision) : NetFinder.Core.Nvr.NvrBrand.Auto;
    using var e = new NetworkEngine(new Settings());
    e.LoadAdapters();
    try
    {
        var r = await NetFinder.Core.Nvr.NvrClient.ReadAsync(new Uri(args[1]), args[2], args[3], brand, CancellationToken.None);
        Console.WriteLine($"NVR brand={r.BrandName} name={r.Name} model={r.Model} serial={r.Serial} fw={r.Firmware} cams={r.Cameras.Count}");
        foreach (var c in r.Cameras)
            Console.WriteLine($"CAM ch={c.Channel} name={c.Name} ip={c.Ip} port={c.Port} model={c.Model} sn={c.Serial} mac={c.Mac} proto={c.Protocol} online={c.Online} status={c.Status}");
        foreach (var n in r.Notes) Console.WriteLine("NOTE " + n);
        var nvrDev = e.Store.ObserveIp(System.Net.IPAddress.Parse(new Uri(args[1]).Host), "Ping", null);
        Console.WriteLine("ADDED " + NetFinder.Core.Nvr.NvrClient.AddToStore(e.Store, nvrDev, r));
        foreach (var d in e.Store.All.OrderBy(d => d.Key))
            lock (d) Console.WriteLine($"DEV {d.Key,-16} type={d.Type} [{d.TypeReason}] host={d.Hostname} model={d.Model} vendor={d.Vendor} reach={d.Reachable} routed={d.Routed} nvr={d.BehindNvr} via=[{string.Join(",", d.Sources)}] info=[{string.Join("; ", d.Info.Select(kv => kv.Key + "=" + kv.Value))}]");
    }
    catch (NetFinder.Core.Nvr.NvrException ex) { Console.WriteLine($"NVRERROR wrongPassword={ex.WrongPassword} {ex.Message}"); }
    return;
}

// Model mode: NetFinder.Probe enrich <ip> <port,port,...>   (runs the port check + every enricher on one IP)
if (args.Length >= 2 && args[0] == "enrich")
{
    using var e = new NetworkEngine(new Settings { SnmpCommunities = Environment.GetEnvironmentVariable("NF_SNMP") ?? "public" });
    e.LogMessage += m => Console.WriteLine("LOG " + m);
    e.LoadAdapters();
    var ip = System.Net.IPAddress.Parse(args[1]);
    var dev = e.Store.ObserveIp(ip, "Ping", null);
    var ports = args.Length > 2 ? args[2].Split(',').Select(int.Parse).ToList() : null;
    var sw = System.Diagnostics.Stopwatch.StartNew();
    await e.CheckPortsAsync(dev, CancellationToken.None, ports);
    lock (dev)
    {
        Console.WriteLine($"DEV {dev.Key} took={sw.ElapsedMilliseconds}ms type={dev.Type} [{dev.TypeReason}] model={dev.Model} (from {dev.ModelSource}, rank {dev.ModelRank}) host={dev.Hostname} vendor={dev.Vendor} via=[{string.Join(",", dev.Sources)}] ports=[{string.Join(",", dev.OpenPorts)}]");
        foreach (var kv in dev.Info) Console.WriteLine($"     {kv.Key} = {kv.Value}");
    }
    return;
}
// IPP: NetFinder.Probe ipp <ip> [path]
if (args.Length >= 2 && args[0] == "ipp")
{
    var a = await NetFinder.Core.Net.Ipp.GetPrinterAttributesAsync(System.Net.IPAddress.Parse(args[1]), CancellationToken.None, 631, args.Length > 2 ? new[] { args[2] } : null);
    if (a == null) Console.WriteLine("IPP no answer");
    else foreach (var kv in a) Console.WriteLine($"IPP {kv.Key} = {kv.Value}");
    return;
}
// Export: NetFinder.Probe export <dir>  (sample devices → .xlsx / .csv / .html)
if (args.Length >= 1 && args[0] == "demo")
{
    using var e = new NetworkEngine(new Settings());
    e.Adapters.Add(NetFinder.Core.Demo.DemoNetwork.Adapter());
    NetFinder.Core.Demo.DemoNetwork.Fill(e);
    foreach (var d in e.Store.All.OrderBy(d => d.Ip?.ToString()))
        Console.WriteLine($"{d.Ip,-14} {d.EffectiveType,-22} reach={d.Reachable,-5} self={d.IsSelf,-5} {d.DisplayName,-24} {d.Model,-26} {d.Vendor}  [{d.TypeReason}]");
    return;
}

if (args.Length >= 2 && args[0] == "export")
{
    using var e = new NetworkEngine(new Settings());
    e.LoadAdapters();
    var a = e.Store.ObserveIp(System.Net.IPAddress.Parse("10.10.20.1"), "Ping", null, d => { d.Info["Is my gateway"] = "yes"; d.OfferModel("Archer C6 2.0", "UPnP", 75); d.Vendor = "TP-Link"; d.OpenPorts.Add(80); d.OpenPorts.Add(443); });
    e.Store.ObserveIp(System.Net.IPAddress.Parse("10.10.20.31"), "Ping", null, d => { d.OfferModel("HP LaserJet Pro M404dn", "IPP", 85); d.Info["Serial number"] = "PHBQB12345"; d.OpenPorts.Add(9100); d.Hostname = "Printer <2nd floor> & \"A\""; });
    e.Store.ObserveIp(System.Net.IPAddress.Parse("192.168.5.11"), "NVR", null, d => { d.BehindNvr = "10.10.20.64"; d.Routed = false; d.Info["NVR channel"] = "10.10.20.64  channel 1"; d.Info["Status on NVR"] = "Online"; d.OfferModel("DS-2CD1043G0-I", "NVR", 90); d.Hostname = "بوابة"; });
    e.Store.ObserveIp(System.Net.IPAddress.Parse("10.10.20.64"), "Ping", null, d => { d.Info["NVR cameras"] = "8"; d.OfferModel("DS-7608NI-K2/8P", "Hikvision API", 90); });
    e.Store.ObserveIp(System.Net.IPAddress.Parse("10.10.20.2"), "Ping", null, d => { d.OfferModel("Old switch", "SNMP", 80); foreach (var p in new[] { 21, 23, 80 }) d.OpenPorts.Add(p); });
    for (var n = 100; n < 100 + int.Parse(Environment.GetEnvironmentVariable("NF_MANY") ?? "0"); n++)
        e.Store.ObserveIp(System.Net.IPAddress.Parse($"10.10.21.{n}"), "Ping", null, d => { d.Hostname = $"pc-{n}"; d.OpenPorts.Add(445); });
    e.Store.ObserveIp(System.Net.IPAddress.Parse("10.10.20.50"), "Ping", null, d => { d.Info["Windows"] = "Windows 11 Pro (10.0.22631)"; d.Info["CPU"] = "Intel(R) Core(TM) i5-11500 @ 2.70GHz"; d.Info["RAM"] = "16 GB"; d.Info["Disk"] = "SAMSUNG MZVLB256HAHQ (NVMe SSD, 256 GB)  +  ST1000DM010 (HDD, 1 TB)"; d.Info["Drives"] = "C: 238 GB (120 GB free)  +  D: 932 GB (610 GB free)"; d.Info["Graphics"] = "Intel(R) UHD Graphics 750 (1 GB)"; d.OfferModel("Dell OptiPlex 7090", "Windows (WMI)", 100); d.Hostname = "ACC-PC1"; });
    // the picture path for Arabic text (the Windows app draws it with GDI+; here a fixed test picture)
    var png = Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAKAAAAAoCAYAAAB5LPGYAAACyUlEQVR4nO3cT4iPQRzH8fdv/awDapOmLZcpDspwlMOSovUnJcmJUCiliPxZJzlR/hxQanEhEUXJiUKxl025zB4cZI6a025JaP84PPPj6WnDr2czm/28TjPPzM7M4bPf53nq6dd4urh7ApFMOnIfQGY2BVCyapY7Wz58auQ6iMwc5cc+VUDJSgGUrBRAyUoBlKwUQMlKAZSsFEDJSgGUrBRAyUoBlKyaf57yi7HuCzAINID5wFFgAXAkTekB3qT2NeBmDL6rzT2WAWti8Nd/M6cvBn++nXVlemorgMD3GPxaAGPdcuBuDH4F8DhdG26Np/7Ndg8Ugx8Chv4wrQ9QAP8D7QawzAOL6mxurBsGbgCrgAlgTwz+Ywpyl7FuIdBPUWW/A7uAQ8A8Y92zGHxva255zVY/rf8YeAfcAa4C3UAncDwGP1jn/FJfnWfAXuBFzf3nAG9j8Kspgna5Mn4JeJiq6j3gbAz+DPA5Bt/7l+vfj8FfAS4AV2Pw6ymC3F/z7DIF2q2Anca6V8BsYCmwrOb+E6TbN/AQuFgZXwccSO3bwKO/WLP8TzUGPE/tDcASY11rbK6xblYMfqzdQ8vUqfMMeBLYS71nsXGKkLR8q4zPonjhIQVlZJI1fgbOWNdFcXttGY3Bj6d2E9gYg/9qrOsAehS+/Orcgp8DK2vu3wQ2p/YO4GVlfBDYCmCs22+sO5eud6QQAYykN2eAnRRVdTIDwLbU3gScrnl2mQJ1XkLeAyuMdR2lKlPVaax7U+oPxOBPlfpfge3GuhPAMLCv8vfHgFvGukMU1W93uv4aeAJsAQ4DD4x1kSKw1SrachToN9YdBEb5dWuXjBrlz6P/9Sf51TdYmRn0Sb5MG1kDqOonqoCSlQIoWSmAkpUCKFkpgJKVAihZKYCSlQIoWSmAkpUCKFkpgJKVAihZNfQj5ZKTKqBkpQBKVj8A4zDAx40fkn4AAAAASUVORK5CYII=");
    NetFinder.Core.Export.PdfReport.ComplexText = (text, size, bold) => new NetFinder.Core.Export.PdfReport.Picture(png, 40, 10);
    string Watch(Device d) => d.Ip?.ToString() switch { "10.10.20.31" => "Down since 10:42", "10.10.20.1" => "Up · 2 ms", _ => "" };
    foreach (var ext in new[] { "xlsx", "csv", "html", "pdf" })
        NetFinder.Core.Export.Exporter.Save(Path.Combine(args[1], "devices." + ext), e.Store.All, "Network devices – test", Watch);
    Console.WriteLine("EXPORTED");
    return;
}
// Changelog: NetFinder.Probe changelog
if (args.Length >= 1 && args[0] == "changelog")
{
    var all = NetFinder.Core.Update.Changelog.All;
    Console.WriteLine($"versions: {string.Join(", ", all.Select(e => e.Version))}");
    Console.WriteLine("--- one version:\n" + NetFinder.Core.Update.Changelog.Text(all.Take(1)));
    Console.WriteLine("--- two versions:\n" + NetFinder.Core.Update.Changelog.Text(all.Take(2)));
    Console.WriteLine("--- banner: " + NetFinder.Core.Update.Changelog.OneLine(string.Join("\n", all[0].Items.Select(i => "- " + i))));
    Console.WriteLine("--- banner (generated notes): [" + NetFinder.Core.Update.Changelog.OneLine("## What's Changed\n* 1.1.6 by @x in #1\n\n**Full Changelog**: https://x") + "]");
    return;
}
// Offline checks of the 1.1.8 parsers: NetFinder.Probe selftest
if (args.Length >= 1 && args[0] == "selftest")
{
    var fails = 0;
    void Check(string what, object? got, object? want)
    {
        var ok = Equals(got?.ToString(), want?.ToString());
        if (!ok) fails++;
        Console.WriteLine($"{(ok ? "OK  " : "FAIL")} {what}: {got ?? "null"}{(ok ? "" : $"   (want {want ?? "null"})")}");
    }
    // SMBIOS: header + type 0, 1, 2, 3, 17 (8 GB), 17 (32 GB extended), 17 (empty slot), 127
    var t = new List<byte>();
    void Struct(byte type, byte[] formatted, params string[] strings)
    {
        t.Add(type); t.Add((byte)(formatted.Length + 4)); t.Add(0); t.Add(0); t.AddRange(formatted);
        if (strings.Length == 0) { t.Add(0); t.Add(0); return; }
        foreach (var x in strings) { t.AddRange(System.Text.Encoding.ASCII.GetBytes(x)); t.Add(0); }
        t.Add(0);
    }
    Struct(0, new byte[] { 1, 2, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, "Dell Inc.", "1.21.0", "05/10/2024");
    // version string index 0 = "none" (SMBIOS has no empty strings)
    var t1 = new byte[0x1B - 4]; t1[0] = 1; t1[1] = 2; t1[2] = 0; t1[3] = 3; t1[0x19 - 4] = 4; t1[0x1A - 4] = 5;
    Struct(1, t1, "Dell Inc.", "OptiPlex 7090", "8XK2QJ3", "0A8E", "OptiPlex");
    Struct(2, new byte[] { 1, 2, 0, 0 }, "Dell Inc.", "0K0WPK");
    Struct(3, new byte[] { 1, 3, 0, 2 }, "Dell Inc.", "CHASSIS1");
    var m8 = new byte[0x22 - 4]; BitConverter.GetBytes((ushort)8192).CopyTo(m8, 0x0C - 4); Struct(17, m8);
    var m32 = new byte[0x22 - 4]; BitConverter.GetBytes((ushort)0x7FFF).CopyTo(m32, 0x0C - 4); BitConverter.GetBytes(32768u).CopyTo(m32, 0x1C - 4); Struct(17, m32);
    var m0 = new byte[0x22 - 4]; Struct(17, m0);
    Struct(127, Array.Empty<byte>());
    var blob = new List<byte> { 0, 3, 4, 0 }; blob.AddRange(BitConverter.GetBytes(t.Count)); blob.AddRange(t);
    var sm = NetFinder.Core.Net.Smbios.Parse(blob.ToArray());
    Check("smbios maker", sm?.Manufacturer, "Dell Inc.");
    Check("smbios product", sm?.Product, "OptiPlex 7090");
    Check("smbios version (empty string)", sm?.Version, null);
    Check("smbios serial", sm?.Serial, "8XK2QJ3");
    Check("smbios family", sm?.Family, "OptiPlex");
    Check("smbios board", $"{sm?.BoardMaker} {sm?.BoardProduct}", "Dell Inc. 0K0WPK");
    Check("smbios chassis serial", sm?.ChassisSerial, "CHASSIS1");
    Check("smbios bios", sm?.BiosVersion, "1.21.0");
    Check("smbios ram GB", sm == null ? null : sm.RamBytes / 1073741824, 40);
    Check("smbios garbage", NetFinder.Core.Net.Smbios.Parse(new byte[] { 1, 2, 3 }), null);

    // user name spellings
    string Sp(string u, string? h = null) => string.Join(" | ", NetFinder.Core.Net.WindowsNames.UserSpellings(u, h));
    Check("spell dns\\user", Sp(@"almada.local\administrator"), @"ALMADA\administrator | administrator@almada.local | almada.local\administrator");
    Check("spell dns\\user + hint", Sp(@"almada.local\administrator", "ALMADA-HQ"), @"ALMADA-HQ\administrator | ALMADA\administrator | administrator@almada.local | almada.local\administrator");
    Check("spell upn", Sp("administrator@almada.local", "ALMADA"), @"administrator@almada.local | ALMADA\administrator");
    Check("spell netbios", Sp(@"ALMADA\administrator", "ALMADA"), @"ALMADA\administrator");
    Check("spell bare", Sp("administrator"), "administrator");
    Check("spell workgroup hint ignored", Sp(@"x.local\a", "WORKGROUP"), @"X\a | a@x.local | x.local\a");

    // UPnP: software agents on PCs are not models
    NetFinder.Core.Net.UpnpDescription U(string? n, string? num) => new(null, null, n, num, null, null, null, null);
    Check("upnp HP agent", U("ProductAgent1.0", "1-00-00").Model, null);
    Check("upnp windows media", U("Windows Media Player Sharing", "12.0").Model, null);
    Check("upnp router", U("Archer C6", "2.0").Model, "Archer C6 2.0");
    Check("upnp nas", U("WDMyCloudEX4100", "BWZE").Model, "WDMyCloudEX4100 BWZE");

    // NetBIOS node status: unique <00> = PC name, group <00> = domain; "*" never becomes a name
    var ns = new List<byte>(new byte[12]); ns.Add(32); ns.AddRange(System.Text.Encoding.ASCII.GetBytes("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")); ns.Add(0);
    ns.AddRange(new byte[] { 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0 });
    var names = new (string n, byte suf, bool grp)[] { ("ALMADA", 0, true), ("AHMED-SAMY", 0, false), ("AHMED-SAMY", 0x20, false), ("ALMADA", 0x1e, true) };
    ns.Add((byte)names.Length);
    foreach (var (n, suf, grp) in names) { ns.AddRange(System.Text.Encoding.ASCII.GetBytes(n.PadRight(15))); ns.Add(suf); ns.Add((byte)(grp ? 0x84 : 0x04)); ns.Add(0); }
    var nb = NetFinder.Core.Analyzers.NetbiosAnalyzer.ParseNodeStatus(ns.ToArray(), out var grpName);
    Check("nbstat name", nb, "AHMED-SAMY");
    Check("nbstat domain", grpName, "ALMADA");
    var star = new byte[34]; star[0] = 32; var enc = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"u8.ToArray(); enc.CopyTo(star, 1);
    Check("decode '*' name", NetFinder.Core.Analyzers.NetbiosAnalyzer.DecodeName(star, out var sfx), "*");

    // classifier: Dell with only web ports is not a Windows PC; Dell with nothing open still is; iDRAC title
    var cl = new NetFinder.Core.Classifiers.BuiltInClassifier();
    string Type(Action<Device> set)
    {
        var d = new Device("10.0.0.250", "E4:43:4B:8E:19:44", System.Net.IPAddress.Parse("10.0.0.250"));
        set(d);
        var sc = new NetFinder.Core.Plugins.TypeScores();
        cl.Score(d, sc);
        return sc.Best is { Score: >= 20 } b ? b.Type : DeviceTypes.Unknown;
    }
    Check("dell 80/443/8000", Type(d => { d.Vendor = "Dell Inc."; d.PortsCheckedAt = DateTime.Now; d.OpenPorts.UnionWith(new[] { 80, 443, 8000 }); }), DeviceTypes.Linux);
    Check("dell no ports", Type(d => { d.Vendor = "Dell Inc."; d.PortsCheckedAt = DateTime.Now; }), DeviceTypes.WindowsPc);
    Check("dell 135/445", Type(d => { d.Vendor = "Dell Inc."; d.PortsCheckedAt = DateTime.Now; d.OpenPorts.UnionWith(new[] { 135, 139, 445 }); }), DeviceTypes.WindowsPc);
    Check("dell idrac title", Type(d => { d.Vendor = "Dell Inc."; d.PortsCheckedAt = DateTime.Now; d.OpenPorts.UnionWith(new[] { 80, 443 }); d.PortInfo[443] = "Integrated Dell Remote Access Controller 9"; }), DeviceTypes.Linux);
    Check("hp 135/139/445", Type(d => { d.Vendor = "Hewlett Packard"; d.PortsCheckedAt = DateTime.Now; d.OpenPorts.UnionWith(new[] { 135, 139, 445 }); }), DeviceTypes.WindowsPc);
    // disk / graphics text
    Check("disk size 500GB", NetFinder.Core.Net.HardwareText.DiskSize(500107862016), "500 GB");
    Check("disk size 256GB", NetFinder.Core.Net.HardwareText.DiskSize(256060514304), "256 GB");
    Check("disk size 1TB", NetFinder.Core.Net.HardwareText.DiskSize(1000204886016), "1 TB");
    Check("disk size 2TB", NetFinder.Core.Net.HardwareText.DiskSize(2000398934016), "2 TB");
    Check("vram 4GB", NetFinder.Core.Net.HardwareText.MemorySize(4294967296), "4 GB");
    Check("vram 512MB", NetFinder.Core.Net.HardwareText.MemorySize(536870912), "512 MB");
    Check("drive 476GB", NetFinder.Core.Net.HardwareText.MemorySize(511504035840), "476 GB");
    Check("disk ssd msft", NetFinder.Core.Net.HardwareText.Disk("SAMSUNG MZVLB256HAHQ-000H1", NetFinder.Core.Net.HardwareText.DiskKind(4, 17, "SAMSUNG MZVLB256HAHQ-000H1"), 256060514304), "SAMSUNG MZVLB256HAHQ-000H1 (NVMe SSD, 256 GB)");
    Check("disk hdd msft", NetFinder.Core.Net.HardwareText.Disk("ST1000DM010-2EP102", NetFinder.Core.Net.HardwareText.DiskKind(3, 11, "ST1000DM010-2EP102"), 1000204886016), "ST1000DM010-2EP102 (HDD, 1 TB)");
    Check("disk ssd by name", NetFinder.Core.Net.HardwareText.Disk("Samsung SSD 860 EVO 500GB", NetFinder.Core.Net.HardwareText.DiskKind(null, null, "Samsung SSD 860 EVO 500GB"), 0), "Samsung SSD 860 EVO 500GB");
    Check("disk hdd by name", NetFinder.Core.Net.HardwareText.DiskKind(0, null, "WDC WD10EZEX-08WN4A0"), "HDD");
    Check("disk kingston by name", NetFinder.Core.Net.HardwareText.DiskKind(0, 11, "KINGSTON SA400S37240G"), "SSD");
    Check("disk unknown", NetFinder.Core.Net.HardwareText.DiskKind(0, 11, "Generic Disk XYZ"), null);
    Check("disk from instance nvme", NetFinder.Core.Net.HardwareText.DiskFromInstance(@"SCSI\Disk&Ven_NVMe&Prod_Samsung_SSD_970\5&2d6a7a0b&0&000000"), "NVMe Samsung SSD 970");
    Check("disk from instance ide", NetFinder.Core.Net.HardwareText.DiskFromInstance(@"IDE\DiskST1000DM003-1CH162___________________CC47____\5&1a2b"), "ST1000DM003-1CH162 CC47");
    Check("disk from instance sata", NetFinder.Core.Net.HardwareText.DiskFromInstance(@"SCSI\Disk&Ven_&Prod_KINGSTON_SA400S3\4&1"), "KINGSTON SA400S3");
    Check("disk from instance usb", NetFinder.Core.Net.HardwareText.DiskFromInstance(@"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer\1"), null);
    Check("gpu", NetFinder.Core.Net.HardwareText.Gpu("NVIDIA GeForce GTX 1050 Ti", 4294967296), "NVIDIA GeForce GTX 1050 Ti (4 GB)");
    Check("gpu rdp filtered", NetFinder.Core.Net.HardwareText.IsSoftwareDisplay("Microsoft Remote Display Adapter"), true);
    Check("gpu intel kept", NetFinder.Core.Net.HardwareText.IsSoftwareDisplay("Intel(R) HD Graphics 630"), false);
    {
        // two disks: SSD + HDD from two registry sources, and two identical disks in one PC
        var H = typeof(NetFinder.Core.Net.HardwareText);
        Check("disk kind samsung oem", NetFinder.Core.Net.HardwareText.DiskKind(null, null, "SAMSUNG MZ7LN256HAJQ-000H1"), "SSD");
        Check("disk kind toshiba hdd", NetFinder.Core.Net.HardwareText.DiskKind(null, null, "TOSHIBA DT01ACA100"), "HDD");
        Check("disk kind st hdd", NetFinder.Core.Net.HardwareText.DiskKind(null, null, "ST1000DM010-2EP102"), "HDD");
        Check("disk kind wdc hdd", NetFinder.Core.Net.HardwareText.DiskKind(null, null, "WDC WD10EZEX-75WN4A0"), "HDD");
        Check("disk kind wd ssd", NetFinder.Core.Net.HardwareText.DiskKind(null, null, "WDS500G2B0A-00SM50"), "SSD");
        Check("same disk prefix", NetFinder.Core.Net.HardwareText.SameDisk("NVMe Samsung SSD 970", "Samsung SSD 970 EVO Plus 500GB"), true);
        Check("same disk different", NetFinder.Core.Net.HardwareText.SameDisk("ST1000DM010-2EP102", "SAMSUNG MZ7LN256HAJQ-000H1"), false);
        Check("clean disk name", NetFinder.Core.Net.HardwareText.CleanDiskName("ST1000DM003-1CH162 ATA Device"), "ST1000DM003-1CH162");
        Check("clean disk name nvme", NetFinder.Core.Net.HardwareText.CleanDiskName("Samsung SSD 970 EVO 500GB NVMe Disk Device"), "Samsung SSD 970 EVO 500GB");
        Check("scsi id ata", NetFinder.Core.Net.HardwareText.DiskFromScsiIdentifier("ATA     ST1000DM010-2EP1CC43"), "ST1000DM010-2EP1");
        Check("scsi id nvme", NetFinder.Core.Net.HardwareText.DiskFromScsiIdentifier("NVMe    Samsung SSD 970 2B2Q"), "Samsung SSD 970");
        Check("scsi id vendor", NetFinder.Core.Net.HardwareText.DiskFromScsiIdentifier("VMware  Virtual disk    2.0 "), "VMware Virtual disk");
        var E = (string n, int? m, int? b, long sz) => new NetFinder.Core.Net.HardwareText.DiskEntry(n, m, b, sz);
        // registry: Services\disk\Enum had only the SSD; DEVICEMAP\Scsi has both
        var merged = NetFinder.Core.Net.HardwareText.MergeDisks(
            new() { E("SAMSUNG MZ7LN256HAJQ-000H1", null, null, 0) },
            new() { E("SAMSUNG MZ7LN256HAJQ-000", null, null, 0), E("ST1000DM010-2EP1", null, null, 0) });
        Check("merge ssd+hdd", string.Join(" | ", merged.Select(NetFinder.Core.Net.HardwareText.Disk)), "SAMSUNG MZ7LN256HAJQ-000H1 (SSD, 256 GB) | ST1000DM010-2EP1 (HDD, 1 TB)");
        // WMI: MSFT_PhysicalDisk + Win32_DiskDrive, two identical HDDs stay two
        merged = NetFinder.Core.Net.HardwareText.MergeDisks(
            new() { E("Samsung SSD 860 EVO 500GB", 4, 11, 500107862016), E("ST1000DM010-2EP102", 3, 11, 1000204886016), E("ST1000DM010-2EP102", 3, 11, 1000204886016) },
            new() { E("Samsung SSD 860 EVO 500GB", null, null, 500105249280), E("ST1000DM010-2EP102", null, null, 1000202273280), E("ST1000DM010-2EP102", null, null, 1000202273280) });
        Check("merge two identical", string.Join(" | ", merged.Select(NetFinder.Core.Net.HardwareText.Disk)),
            "Samsung SSD 860 EVO 500GB (500 GB) | ST1000DM010-2EP102 (HDD, 1 TB) | ST1000DM010-2EP102 (HDD, 1 TB)");
        // MSFT_PhysicalDisk missed the HDD (hot-plug SATA port): Win32_DiskDrive adds it with its size
        merged = NetFinder.Core.Net.HardwareText.MergeDisks(
            new() { E("Samsung SSD 860 EVO 500GB", 4, 11, 500107862016) },
            new() { E("Samsung SSD 860 EVO 500GB", null, null, 500105249280), E("TOSHIBA DT01ACA100", null, null, 1000204886016) });
        Check("merge adds missing hdd", string.Join(" | ", merged.Select(NetFinder.Core.Net.HardwareText.Disk)),
            "Samsung SSD 860 EVO 500GB (500 GB) | TOSHIBA DT01ACA100 (HDD, 1 TB)");
        // disk sizes from the model name (the registry has none)
        foreach (var (model, want) in new[] {
            ("WD2002FYPS-12", "2 TB"), ("WDC WD10EZEX-08WN4A0", "1 TB"), ("WDC WD5000AAKX-08U6AA0", "500 GB"), ("WD20EZRZ-00Z5HB0", "2 TB"),
            ("WDC WD3200AAJS-00L7A0", "320 GB"), ("WD100EFAX-68LHPN0", "10 TB"), ("ST1000DM010-2EP102", "1 TB"), ("ST500LM030-2E717D", "500 GB"),
            ("ST3500418AS", "500 GB"), ("ST31000524AS", "1 TB"), ("TOSHIBA DT01ACA100", "1 TB"), ("TOSHIBA DT01ACA050", "500 GB"),
            ("TOSHIBA HDWD120", "2 TB"), ("KINGSTON SA400S37480G", "480 GB"), ("KINGSTON SA400S37240G", "240 GB"), ("SAMSUNG MZ7LN256HAJQ-000H1", "256 GB"),
            ("SAMSUNG MZVLB512HBJQ-000L7", "512 GB"), ("Samsung SSD 860 EVO 500GB", "500 GB"), ("CT500MX500SSD1", "500 GB"), ("WDS100T2B0A-00SM50", "1 TB"),
            ("SK hynix HFS256G39TND-N210A", "256 GB"), ("INTEL SSDSC2KW256G8", "256 GB"), ("KBG40ZNS256G NVMe KIOXIA 256GB", "256 GB"),
            ("SNV2S1000G", "1 TB"), ("VMware Virtual disk", ""), ("Generic Disk XYZ", "") })
            Check("size from model " + model, NetFinder.Core.Net.HardwareText.DiskSize(NetFinder.Core.Net.HardwareText.SizeFromModel(model)), want);
        Check("disk with model size", NetFinder.Core.Net.HardwareText.Disk("WD2002FYPS-12", "HDD", 0), "WD2002FYPS-12 (HDD, 2 TB)");
        Check("disk real size wins", NetFinder.Core.Net.HardwareText.Disk("KINGSTON SA400S37480G", "SSD", 480103981056), "KINGSTON SA400S37480G (SSD, 480 GB)");
        // the Log tab's per-device filter
        var f = NetFinder.Core.Model.LogFilter.For("10.0.0.1", "64:00:6A:55:0E:5E", new[] { "madapc0165.almada.local", "*", null }, false)!;
        Check("log ip", f.IsMatch("21:27:14  Windows 10.0.0.1 (Dell): ports closed"), true);
        Check("log ip not prefix", f.IsMatch("21:27:14  Windows 10.0.0.12: VMware"), false);
        Check("log ip in list", f.IsMatch("Windows summary: 2 PC(s): 10.0.0.14, 10.0.0.1"), true);
        Check("log ip not suffix", f.IsMatch("Windows 110.0.0.1: x"), false);
        Check("log mac dash", f.IsMatch("seen 64-00-6a-55-0e-5e"), true);
        Check("log name", f.IsMatch("NetBIOS: MADAPC0165 is in ALMADA"), true);
        Check("log other", f.IsMatch("ARP sweep pass 1 on Ethernet: 65533 addresses"), false);
    }
    {
        // 1.1.15: risky ports
        string Risk(params int[] p) => string.Join(" | ", NetFinder.Core.Net.PortRisk.Check(p).Select(x => $"{x.Port} {x.Service} {x.Level}"));
        Check("risk telnet+ftp+web", Risk(80, 23, 21, 443), "21 FTP High | 23 Telnet High");
        Check("risk http only", Risk(80), "80 HTTP Note");
        Check("risk rdp smb", Risk(3389, 445, 135), "445 SMB (file sharing) Note | 3389 Remote Desktop Note");
        Check("risk vnc once", Risk(5800, 5900), "5900 VNC High");
        Check("risk none", Risk(22, 443, 9100), "");
        Check("risky text", NetFinder.Core.Net.PortRisk.RiskyText(new[] { 23, 80, 6379, 3389 }), "23 Telnet, 6379 Redis");
        // old settings files have no PortsVersion: it must read as 0 so the new ports get added once
        var old = System.Text.Json.JsonSerializer.Deserialize<Settings>("{\"Ports\":[80,443]}")!;
        Check("old settings PortsVersion", old.PortsVersion, 0);
        Check("default ports have the risky ones", NetFinder.Core.Net.PortRisk.ExtraPorts.All(p => new Settings().Ports.Contains(p)), true);
        Check("watch defaults", $"{old.WatchSeconds} {old.WatchSound} {old.Watch.Count}", "60 True 0");

        // 1.1.15: watching devices (fake ping: .2 goes down after the first round, .3 never answers)
        var downNow = false;
        var calls = new System.Collections.Concurrent.ConcurrentDictionary<string, int>();
        using var w = new NetFinder.Core.Monitoring.Watcher((ip, ct) =>
        {
            calls.AddOrUpdate(ip.ToString(), 1, (_, n) => n + 1);
            var up = ip.ToString() switch { "10.0.0.2" => !downNow, "10.0.0.3" => false, _ => true };
            return Task.FromResult(new NetFinder.Core.Monitoring.ProbeResult(up, up ? 3 : null, up ? "ping" : ""));
        }) { RetryDelay = TimeSpan.FromMilliseconds(5) };
        var events = new System.Collections.Concurrent.ConcurrentQueue<string>();
        w.Changed += (s, before) => events.Enqueue($"{s.Ip} {before}->{s.Health}");
        w.SetTargets(new[] { "10.0.0.1", "10.0.0.2", "10.0.0.3", "not an ip" });
        Check("watch targets", w.Count, 3);
        await w.CheckAllAsync(CancellationToken.None);
        Check("watch first round", string.Join(", ", events.OrderBy(x => x)), "10.0.0.1 Unknown->Up, 10.0.0.2 Unknown->Up, 10.0.0.3 Unknown->Down");
        Check("watch tries a silent device 3 times", calls["10.0.0.3"], 3);
        Check("watch pings an up device once", calls["10.0.0.1"], 1);
        events.Clear(); downNow = true;
        await w.CheckAllAsync(CancellationToken.None);
        Check("watch goes down", string.Join(", ", events), "10.0.0.2 Up->Down");
        events.Clear();
        await w.CheckAllAsync(CancellationToken.None);
        Check("watch no repeat alert", events.Count, 0);
        downNow = false;
        await w.CheckAllAsync(CancellationToken.None);
        Check("watch comes back", string.Join(", ", events), "10.0.0.2 Down->Up");
        Check("watch rtt", w.Get("10.0.0.2")?.Ms, 3);
        // the loop: a device added while running is checked right away (not after the 1-minute interval)
        w.Start();
        await Task.Delay(300);
        w.SetTargets(new[] { "10.0.0.1", "10.0.0.9" });
        await Task.Delay(400);
        Check("watch new target checked now", w.Get("10.0.0.9")?.Health, NetFinder.Core.Monitoring.Health.Up);
        Check("watch removed target", w.Get("10.0.0.3") == null, true);
        w.Stop();
    }
    Console.WriteLine(fails == 0 ? "ALL OK" : $"{fails} FAILED");
    return;
}
// ONVIF multicast scan from one local address: NetFinder.Probe onvif <localIp>
if (args.Length >= 2 && args[0] == "onvif")
{
    foreach (var i in await NetFinder.Core.Net.WsDiscovery.ProbeAllAsync(System.Net.IPAddress.Parse(args[1]), 2000, CancellationToken.None))
        Console.WriteLine($"ONVIF {i.From} hw={i.Hardware} name={i.Name} loc={i.Location} types={i.Types} xaddrs={i.XAddrs}");
    return;
}

var iface = args.Length > 0 ? args[0] : "eth0";
var secs = args.Length > 1 ? int.Parse(args[1]) : 5;
var settings = new Settings { ProbeSubnets = new() { "192.168.1.0/24", "192.168.0.0/24" }, FramesPerSecond = 3000,
    ScanRanges = Environment.GetEnvironmentVariable("NF_RANGE") ?? "" };
using var eng = new NetworkEngine(settings);
eng.LogMessage += m => Console.WriteLine("LOG " + m);
eng.Store.Removed += d => Console.WriteLine("REMOVED " + d.Key);
eng.LoadAdapters();
Console.WriteLine($"capture={eng.CaptureAvailable} adapters={string.Join(" | ", eng.Adapters)}");
var ad = eng.Adapters.Where(a => a.Id == iface).ToList();
eng.StartListening(ad);
if (args.Contains("scan"))
    await eng.ScanAsync(ad, eng.Plugins.Scanners, new Progress<string>(_ => { }), CancellationToken.None);
await Task.Delay(secs * 1000);
if (args.Contains("ports"))
{
    eng.RefreshAdapterAddresses();
    foreach (var d in eng.Store.All.Where(d => d.Reachable)) await eng.CheckPortsAsync(d, CancellationToken.None);
}
foreach (var d in eng.Store.All.OrderBy(d => d.Key))
{
    lock (d)
    {
        Console.WriteLine($"DEV {d.Key,-16} mac={d.Mac} routed={d.Routed} ip={string.Join(",", d.Ips)} type={d.Type} [{d.TypeReason}] host={d.Hostname} model={d.Model} vendor={d.Vendor} reach={d.Reachable} via=[{string.Join(",", d.Sources)}] ports=[{string.Join(",", d.OpenPorts)}]");
        foreach (var kv in d.Info) Console.WriteLine($"     {kv.Key} = {kv.Value}");
        foreach (var kv in d.PortInfo) Console.WriteLine($"     port {kv.Key}: {kv.Value}");
        if (d.Services.Count > 0) Console.WriteLine($"     services: {string.Join(",", d.Services)}");
    }
}
Console.WriteLine("LEARNED " + string.Join(", ", eng.LearnedSubnets.Keys));
