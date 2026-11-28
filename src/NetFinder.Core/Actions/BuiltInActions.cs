using System.Text.RegularExpressions;
using NetFinder.Core.Model;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Actions;

/// <summary>
/// Buttons shown in the device tab. To add your own, write another IDeviceActionProvider
/// (see docs/PLUGINS.md) — no need to touch this file.
/// </summary>
public sealed class BuiltInActions : IDeviceActionProvider
{
    public static readonly int[] HttpsPorts = { 443, 8443, 4443, 9443, 10443 };
    public static readonly HashSet<int> HttpPorts = new() { 80, 81, 82, 88, 3000, 5000, 5001, 7547, 8000, 8001, 8008, 8080, 8081, 8088, 8888, 8899, 9000, 49152 };

    /// <summary>A plain web port of this device. Port 88 of a Windows machine is Kerberos (a domain controller), not a web page.</summary>
    public static bool IsWebPort(Device d, int p) => HttpPorts.Contains(p) && !(p == 88 && Classifiers.ServerSigns.IsKerberos(d));

    /// <summary>Managed network gear: worth offering SSH/Telnet even before (or without) a port check.</summary>
    public static bool IsNetworkGear(Device d) =>
        d.EffectiveType is DeviceTypes.Switch or DeviceTypes.AccessPoint or DeviceTypes.Router or DeviceTypes.Firewall
        || d.Sources.Contains("LLDP") || d.Sources.Contains("CDP");

    public static bool IsMikroTik(Device d) =>
        d.OpenPorts.Contains(8291) || d.OpenPorts.Contains(8728) ||
        Regex.IsMatch((d.Vendor ?? "") + " " + d.Model + " " + d.Info.GetValueOrDefault("LLDP description") + " " + d.Info.GetValueOrDefault("CDP software"), "routerboard|mikrotik|routeros", RegexOptions.IgnoreCase);

    public IEnumerable<DeviceAction> GetActions(Device d)
    {
        var ip = d.Ip?.ToString();
        if (ip == null) yield break;
        var gear = IsNetworkGear(d);
        var unknownPorts = d.PortsCheckedAt == null || !d.Reachable;

        // Web: always offer 80/443, plus every open web-like port
        yield return new DeviceAction("Web", $"http://{ip}", () => Launcher.Open($"http://{ip}/"), "Open in browser");
        yield return new DeviceAction("Web", $"https://{ip}", () => Launcher.Open($"https://{ip}/"), "Open in browser (HTTPS)");
        foreach (var p in d.OpenPorts)
        {
            if (p is 80 or 443) continue;
            if (HttpsPorts.Contains(p)) yield return new DeviceAction("Web", $"https://{ip}:{p}", () => Launcher.Open($"https://{ip}:{p}/"));
            else if (IsWebPort(d, p)) yield return new DeviceAction("Web", $"http://{ip}:{p}", () => Launcher.Open($"http://{ip}:{p}/"));
        }
        if (d.Info.TryGetValue("UPnP description URL", out var loc))
            yield return new DeviceAction("Web", "UPnP description", () => Launcher.Open(loc), loc);

        // Remote access. Switches/APs/routers always get SSH + Telnet (management is often on one of them).
        if (d.OpenPorts.Contains(22) || gear)
            yield return new DeviceAction("Remote", "SSH", () => Launcher.Ssh(ip),
                d.OpenPorts.Contains(22) ? "Port 22 is open" : unknownPorts ? "Port 22 not checked yet" : "Port 22 looked closed; SSH may be turned off on the device");
        if (d.OpenPorts.Contains(23) || gear)
            yield return new DeviceAction("Remote", "Telnet", () => Launcher.Telnet(ip),
                d.OpenPorts.Contains(23) ? "Port 23 is open" : unknownPorts ? "Port 23 not checked yet" : "Port 23 looked closed; Telnet may be turned off on the device");
        if (IsMikroTik(d)) yield return new DeviceAction("Remote", "Winbox (MikroTik)", () => Launcher.Winbox(ip), "Opens Winbox if it is on this PC, otherwise its download page");
        if (d.OpenPorts.Contains(3389)) yield return new DeviceAction("Remote", "Remote Desktop", () => Launcher.Run("mstsc.exe", $"/v:{ip}"));
        if (d.OpenPorts.Contains(445) || d.OpenPorts.Contains(139)) yield return new DeviceAction("Remote", "Shared folders", () => Launcher.Open($@"\\{ip}"));
        if (d.OpenPorts.Contains(21)) yield return new DeviceAction("Remote", "FTP", () => Launcher.Open($"ftp://{ip}/"));
        if (d.OpenPorts.Contains(5900)) yield return new DeviceAction("Remote", "VNC", () => Launcher.Vnc(ip));
        if (d.OpenPorts.Contains(554))
            yield return new DeviceAction("Remote", "RTSP stream", () => Launcher.OpenWithHint($"rtsp://{ip}:554/", "No video player is set for rtsp:// links. Install VLC, then try again."),
                "Opens in VLC or your default player");
        if (d.OpenPorts.Contains(9100) || d.OpenPorts.Contains(631))
            yield return new DeviceAction("Remote", "Printers (Windows)", () => Launcher.Open("ms-settings:printers"), "Windows printer settings, to add this printer");

        // Tools
        yield return new DeviceAction("Tools", "Ping", () => Launcher.Console($"ping -t {ip}"));
        yield return new DeviceAction("Tools", "Traceroute", () => Launcher.Console($"tracert -d {ip}"));
    }

    /// <summary>
    /// The one best way to open this device (the "Open" column and double-click): its web page on the port that is
    /// open, else Remote Desktop / SSH / Telnet / Winbox / shared folders… Null when nothing to open was found.
    /// </summary>
    public static (string Label, DeviceAction Action)? Primary(Device d)
    {
        var ip = d.Ip?.ToString();
        if (ip == null || d.IsSelf) return null;
        var ports = d.OpenPorts;
        DeviceAction Web(string url) => new("Web", url, () => Launcher.Open(url + "/"));

        if (ports.Contains(80)) return ("http", Web($"http://{ip}"));
        if (ports.Contains(443)) return ("https", Web($"https://{ip}"));
        foreach (var p in ports)
            if (HttpsPorts.Contains(p)) return ($"https :{p}", Web($"https://{ip}:{p}"));
        foreach (var p in ports)
            if (IsWebPort(d, p)) return ($"http :{p}", Web($"http://{ip}:{p}"));
        if (ports.Contains(8291)) return ("Winbox", new DeviceAction("Remote", "Winbox", () => Launcher.Winbox(ip)));
        if (ports.Contains(3389)) return ("Remote Desktop", new DeviceAction("Remote", "Remote Desktop", () => Launcher.Run("mstsc.exe", $"/v:{ip}")));
        if (ports.Contains(22)) return ("SSH", new DeviceAction("Remote", "SSH", () => Launcher.Ssh(ip)));
        if (ports.Contains(23)) return ("Telnet", new DeviceAction("Remote", "Telnet", () => Launcher.Telnet(ip)));
        if (ports.Contains(445) || ports.Contains(139)) return ("Files", new DeviceAction("Remote", "Shared folders", () => Launcher.Open($@"\\{ip}")));
        if (ports.Contains(5900)) return ("VNC", new DeviceAction("Remote", "VNC", () => Launcher.Vnc(ip)));
        if (ports.Contains(21)) return ("FTP", new DeviceAction("Remote", "FTP", () => Launcher.Open($"ftp://{ip}/")));
        if (ports.Contains(554)) return ("RTSP", new DeviceAction("Remote", "RTSP", () => Launcher.OpenWithHint($"rtsp://{ip}:554/", "Install VLC to open rtsp:// links.")));
        // Ports not known yet (other subnet, or not checked): most devices with a UI have a web page.
        if (d.PortsCheckedAt == null) return ("http", Web($"http://{ip}"));
        return null;
    }
}
