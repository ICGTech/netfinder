using System.Text.RegularExpressions;
using NetFinder.Core.Model;
using NetFinder.Core.Plugins;
using T = NetFinder.Core.Model.DeviceTypes;

namespace NetFinder.Core.Classifiers;

/// <summary>
/// Rule-based device type detection. Each rule adds points; strongest total wins.
/// Signals: MAC vendor, hostname, DHCP vendor class, mDNS services, model strings
/// (mDNS / LLDP / CDP / UPnP / web title), open ports and TTL.
/// To add a rule just append a line to one of the tables below.
/// </summary>
public sealed class BuiltInClassifier : IDeviceClassifier
{
    // (regex on MAC vendor, type, points)
    private static readonly (Regex Rx, string Type, int Pts)[] VendorRules = Build(new (string, string, int)[]
    {
        (@"hikvision|dahua|axis comm|uniview|hanwha|vivotek|mobotix|reolink|amcrest|ezviz|tiandy|milesight|imou", T.Camera, 75),
        (@"canon|epson|seiko epson|brother|kyocera|ricoh|lexmark|xerox|konica|sharp corp|oki data|zebra|toshiba tec|pantum|fuji ?xerox|fujifilm business", T.Printer, 70),
        (@"synology|qnap|western digital|seagate|buffalo|netapp|asustor|terramaster|drobo", T.Nas, 75),
        (@"yealink|polycom|grandstream|avaya|snom|fanvil|mitel|cisco spa|audiocodes|htek", T.VoipPhone, 75),
        (@"routerboard|mikrotik", T.Router, 70),
        (@"fortinet|palo alto|sonicwall|watchguard|sophos|check point|barracuda", T.Firewall, 75),
        (@"ubiquiti|ruckus|aruba|cambium|aerohive|meraki|engenius|grandstream", T.AccessPoint, 35),
        (@"cisco|juniper|extreme networks|hewlett packard enterprise|h3c|ruijie|d-link intl|edgecore|allied telesis|netgear|zyxel|dell emc|arista|brocade|hp procurve|procurve", T.Switch, 30),
        (@"tp-link|tenda|d-link|netgear|zte|huawei technologies|fiberhome|sagemcom|technicolor|arcadyan|zyxel|linksys|asustek|sercomm|nokia shanghai|nokia solutions|xiaomi communications|cudy|totolink|edimax", T.Router, 25),
        (@"xiaomi|oppo|vivo|oneplus|realme|honor|motorola mobility|huawei device|transsion|tecno|infinix|itel|nothing technology|meizu|google", T.Android, 35),
        (@"samsung", T.Android, 25),
        (@"lg electronics|tcl|hisense|vizio|roku|skyworth|sony visual|sony corporation|philips|sharp|panasonic|changhong|konka|amlogic", T.Tv, 40),
        (@"apple", T.IPhone, 20),
        (@"sony interactive|nintendo|microsoft.*xbox", T.Console, 70),
        (@"raspberry pi", T.Linux, 60),
        (@"espressif|tuya|shelly|sonoff|itead|broadlink|lumi united|signify|philips lighting|ezviz|wiz connected|ring llc|nest labs|ecobee|amazon technologies", T.Iot, 55),
        (@"intel corporate|realtek|dell inc|lenovo|micro-star|msi|gigabyte|giga-byte|asrock|liteon|azurewave|hon hai|foxconn|quanta|wistron|compal|pegatron|elitegroup|clevo|chicony|hewlett packard$|hp inc", T.WindowsPc, 25),
        (@"vmware|xensource|parallels|qemu|virtualbox|pcs systemtechnik", T.Vm, 75),
        (@"apc|american power|eaton|schneider|vertiv|emerson network|riello|cyberpower", T.Ups, 60),
        (@"zkteco|suprema|hid global|anviz|zk ?tech", T.AccessControl, 80),
    });

    // (regex on hostname / custom name / NetBIOS / mDNS name, type, points)
    private static readonly (Regex Rx, string Type, int Pts)[] NameRules = Build(new (string, string, int)[]
    {
        (@"^android|galaxy|^sm-[a-z]\d|redmi|^mi-|poco|^oppo|^vivo|^huawei-|^honor|oneplus|realme|^moto|pixel|infinix|tecno", T.Android, 65),
        (@"iphone|ipad", T.IPhone, 85),
        (@"macbook|imac|mac-?mini|mac-?pro|mac-?studio", T.Mac, 85),
        (@"^desktop-|^laptop-|^win-|^pc-|-pc$|workstation", T.WindowsPc, 70),
        (@"^npi|^hp[0-9a-f]{6}|^brn|^brw|^epson|^canon|^kyocera|^ricoh|^xerox|^lexmark|laserjet|officejet|deskjet|printer|^km[0-9a-f]{6}", T.Printer, 80),
        (@"ipc|ipcam|camera|^cam|^ds-2cd|hikvision|dahua|nvr|dvr", T.Camera, 60),
        (@"\bnvr\b|\bdvr\b|^ds-7|^ds-9", T.Nvr, 70),
        (@"lgwebostv|webos|samsung.?tv|\[tv\]|bravia|androidtv|android-tv|chromecast|roku|firetv|fire-tv|appletv|apple-tv|^tv|smart.?tv|mibox|shield", T.Tv, 75),
        (@"^sw[-_]|switch|^core-|^dist-|^access-|catalyst|procurve", T.Switch, 45),
        (@"^ap[-_]|^uap|^eap|wap|access.?point|unifi", T.AccessPoint, 50),
        (@"router|gateway|^gw[-_]|mikrotik|openwrt|dd-wrt|fritz|archer|tplinkwifi|^vdsl|^adsl|^hg\d|^zte", T.Router, 55),
        (@"synology|diskstation|qnap|^nas|truenas|freenas|unraid|readynas|mycloud", T.Nas, 80),
        (@"xbox|playstation|^ps[345]|nintendo|switch-console", T.Console, 75),
        (@"raspberrypi|ubuntu|debian|centos|fedora|^srv|server|proxmox|esxi", T.Linux, 50),
        (@"esp[-_]|esp32|esp8266|tasmota|shelly|sonoff|tuya|smart.?plug|echo-|alexa|nest|google-home|googlehome", T.Iot, 65),
        (@"sip|voip|yealink|polycom|grandstream|^sep[0-9a-f]{12}", T.VoipPhone, 70),
        (@"zkteco|attendance|fingerprint", T.AccessControl, 75),
    });

    // (regex on model text: mDNS model/ty, LLDP/CDP description, UPnP server, web title, DHCP vendor class)
    private static readonly (Regex Rx, string Type, int Pts)[] ModelRules = Build(new (string, string, int)[]
    {
        (@"android-dhcp|android", T.Android, 70),
        (@"msft 5\.0|windows", T.WindowsPc, 45),
        (@"laserjet|officejet|deskjet|pagewide|imagerunner|imageclass|pixma|mfc-|dcp-|hl-l|ecotank|workforce|taskalfa|ecosys|bizhub|aficio|printer|ipp", T.Printer, 85),
        (@"hikvision|dahua|ds-2cd|ipc-|ip camera|network camera|webcam|ezviz|reolink|onvif", T.Camera, 80),
        (@"\bnvr\b|\bdvr\b|\b[nxhd]vr\d|ds-7\d|ds-9\d|xvr", T.Nvr, 85),
        (@"webos|tizen|bravia|android ?tv|google tv|chromecast|roku|fire ?tv|smarttv|smart tv|dlnadoc|mediarenderer|kodi|apple ?tv|appletv", T.Tv, 75),
        (@"switch|catalyst|cisco-1\.\d|procurve|aruba \d|nexus|ios-xe|cisco ios|junos ex|comware|powerconnect|cloud ?engine|s5[17]\d\d|sg\d{3}|cbs\d{3}|tl-sg|gs\d{3}|omniswitch", T.Switch, 75),
        (@"access point|unifi ap|uap-|eap\d|instant on ap|airos|wap\d", T.AccessPoint, 75),
        (@"routeros|rosssh|mikrotik|openwrt|dd-wrt|fritz!box|router|gateway|igd|internetgatewaydevice|wanipconnection|wancommoninterface|edgeos|vyos|pfsense|opnsense", T.Router, 65),
        (@"fortigate|fortios|pan-os|sonicwall|sophos|watchguard|checkpoint|asa\d", T.Firewall, 80),
        (@"synology|diskstation|dsm|qnap|qts|truenas|freenas|readynas|my ?cloud|unraid", T.Nas, 85),
        (@"macbook|imac|macmini|mac mini|macpro|mac pro|mac studio|mac\d+,\d", T.Mac, 85),
        (@"iphone|ipad|ipod", T.IPhone, 85),
        (@"xbox|playstation|nintendo", T.Console, 80),
        (@"ubuntu|debian|centos|red hat|linux|raspbian|synology", T.Linux, 20),
        (@"udhcp|dhcpcd-\d.*esp|espressif|tasmota|shelly|tuya|homekit|esp32|esp8266", T.Iot, 50),
        (@"yealink|polycom|grandstream|cisco ip phone|sip-t\d|ip phone|voip", T.VoipPhone, 85),
        (@"ups|smart-ups|powerchute|network management card", T.Ups, 60),
        (@"zkteco|attendance|access control", T.AccessControl, 80),
    });

    // (mDNS service, type, points)
    private static readonly (string Svc, string Type, int Pts)[] ServiceRules =
    {
        ("_ipp._tcp", T.Printer, 80), ("_ipps._tcp", T.Printer, 80), ("_printer._tcp", T.Printer, 80), ("_pdl-datastream._tcp", T.Printer, 80),
        ("_scanner._tcp", T.Printer, 50), ("_uscan._tcp", T.Printer, 50),
        ("_googlecast._tcp", T.Tv, 80), ("_androidtvremote._tcp", T.Tv, 85), ("_androidtvremote2._tcp", T.Tv, 85), ("_amzn-wplay._tcp", T.Tv, 70),
        ("_airplay._tcp", T.Tv, 30), ("_raop._tcp", T.Tv, 20), ("_spotify-connect._tcp", T.Tv, 25),
        ("_companion-link._tcp", T.IPhone, 45), ("_apple-mobdev2._tcp", T.IPhone, 80), ("_rdlink._tcp", T.IPhone, 40),
        ("_afpovertcp._tcp", T.Nas, 40), ("_smb._tcp", T.Nas, 20), ("_adisk._tcp", T.Nas, 40),
        ("_ssh._tcp", T.Linux, 20), ("_workstation._tcp", T.Linux, 30), ("_sftp-ssh._tcp", T.Linux, 15),
        ("_hap._tcp", T.Iot, 70), ("_hap._udp", T.Iot, 70), ("_matter._tcp", T.Iot, 70), ("_esphomelib._tcp", T.Iot, 85),
        ("_device-info._tcp", T.Mac, 10),
    };

    // (port, type, points)
    private static readonly (int Port, string Type, int Pts)[] PortRules =
    {
        (9100, T.Printer, 60), (631, T.Printer, 50), (515, T.Printer, 40),
        (554, T.Camera, 45), (37777, T.Nvr, 60), (8000, T.Camera, 15),
        (3389, T.WindowsPc, 55), (135, T.WindowsPc, 30), (139, T.WindowsPc, 15), (445, T.WindowsPc, 15),
        (62078, T.IPhone, 85),
        (8008, T.Tv, 30), (8009, T.Tv, 45),
        (8291, T.Router, 75), (8728, T.Router, 70), (53, T.Router, 35), (7547, T.Router, 40), (1900, T.Router, 10),
        (5000, T.Nas, 20), (5001, T.Nas, 25),
        (5060, T.VoipPhone, 40),
        (1883, T.Iot, 40),
        (502, T.Iot, 25),
        (22, T.Linux, 10),
    };

    public void Score(Device d, TypeScores s)
    {
        // Strong protocol signals
        if (d.Sources.Contains("LLDP") || d.Sources.Contains("CDP"))
        {
            var desc = (d.Model ?? "") + " " + d.Info.GetValueOrDefault("LLDP description") + " " + d.Info.GetValueOrDefault("CDP software");
            if (Regex.IsMatch(desc, "phone|sip", RegexOptions.IgnoreCase)) s.Add(T.VoipPhone, 60, "LLDP/CDP says phone");
            else if (Regex.IsMatch(desc, @"\bap\b|access point|wireless", RegexOptions.IgnoreCase)) s.Add(T.AccessPoint, 60, "LLDP/CDP says AP");
            else s.Add(T.Switch, 55, "sends LLDP/CDP");
        }
        if (d.Info.ContainsKey("NVR cameras")) s.Add(T.Nvr, 150, "lists its cameras");
        if (d.BehindNvr != null) s.Add(T.Camera, 120, "camera on NVR " + d.BehindNvr);
        if (d.Info.ContainsKey("DHCP server")) s.Add(T.Router, 60, "runs a DHCP server");
        if (d.Info.ContainsKey("Is my gateway")) s.Add(T.Router, 90, "this PC's gateway");
        if (d.Vendor == "(Random / private MAC)") s.Add(T.Phone, 30, "private random MAC (phones do this)");

        Match(VendorRules, d.Vendor, s, "vendor");
        if (d.Info.GetValueOrDefault("Manufacturer") is { } mf && !mf.Equals(d.Vendor, StringComparison.OrdinalIgnoreCase)) Match(VendorRules, mf, s, "maker");
        if (d.Info.GetValueOrDefault("Maker (SNMP)") is { } sm && !sm.Equals(d.Vendor, StringComparison.OrdinalIgnoreCase)) Match(VendorRules, sm, s, "SNMP maker");
        if (d.Info.GetValueOrDefault("ONVIF types")?.Contains("NetworkVideoTransmitter", StringComparison.OrdinalIgnoreCase) == true) s.Add(T.Camera, 60, "ONVIF video device");
        if (d.Sources.Contains("IPP")) s.Add(T.Printer, 80, "answers IPP (printer)");
        if (d.Info.ContainsKey("Windows")) s.Add(T.WindowsPc, 120, "Windows (WMI)");
        foreach (var n in new[] { d.CustomName, d.Hostname, d.Info.GetValueOrDefault("NetBIOS name"), d.Info.GetValueOrDefault("mDNS name"), d.Info.GetValueOrDefault("mDNS friendly name") })
            Match(NameRules, n, s, "name");
        foreach (var m in new[] { d.Model, d.Info.GetValueOrDefault("DHCP vendor class"), d.Info.GetValueOrDefault("UPnP server"),
                     d.Info.GetValueOrDefault("LLDP description"), d.Info.GetValueOrDefault("Web page title"), d.Info.GetValueOrDefault("CDP software"),
                     d.Info.GetValueOrDefault("SNMP description"), d.Info.GetValueOrDefault("ONVIF name"), d.Info.GetValueOrDefault("UPnP model description"),
                     d.Info.GetValueOrDefault("UPnP device type"), d.Info.GetValueOrDefault("Web login realm"), d.Info.GetValueOrDefault("FTP banner"),
                     d.Info.GetValueOrDefault("SSH banner"), d.Info.GetValueOrDefault("Telnet banner"), d.Info.GetValueOrDefault("Windows") })
            Match(ModelRules, m, s, "model");

        foreach (var (svc, type, pts) in ServiceRules)
            if (d.Services.Contains(svc)) s.Add(type, pts, "mDNS " + svc);
        foreach (var (port, type, pts) in PortRules)
            if (d.OpenPorts.Contains(port)) s.Add(type, pts, "port " + port);
        foreach (var info in d.PortInfo.Values) Match(ModelRules, info, s, "web page");

        // Apple: refine iPhone vs Mac
        if (d.Vendor?.Contains("Apple", StringComparison.OrdinalIgnoreCase) == true && (d.OpenPorts.Contains(22) || d.OpenPorts.Contains(445) || d.Services.Contains("_ssh._tcp")))
            s.Add(T.Mac, 40, "Apple + file sharing/SSH");

        if (d.Info.TryGetValue("TTL", out var ttl))
        {
            if (ttl == "128") s.Add(T.WindowsPc, 25, "TTL 128");
            else if (ttl == "255") s.Add(T.Switch, 15, "TTL 255");
        }
    }

    private static void Match((Regex Rx, string Type, int Pts)[] rules, string? text, TypeScores s, string label)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        foreach (var (rx, type, pts) in rules)
            if (rx.IsMatch(text)) { s.Add(type, pts, $"{label} \"{Short(text)}\""); }
    }

    private static string Short(string t) => t.Length > 30 ? t[..30] + "…" : t;

    private static (Regex, string, int)[] Build((string, string, int)[] rules) =>
        rules.Select(r => (new Regex(r.Item1, RegexOptions.IgnoreCase | RegexOptions.Compiled), r.Item2, r.Item3)).ToArray();
}
