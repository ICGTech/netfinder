using NetFinder.Core.Model;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Actions;

/// <summary>
/// Buttons shown in the device tab. To add your own, write another IDeviceActionProvider
/// (see docs/PLUGINS.md) — no need to touch this file.
/// </summary>
public sealed class BuiltInActions : IDeviceActionProvider
{
    private static readonly int[] HttpsPorts = { 443, 8443, 4443, 9443, 10443 };
    private static readonly HashSet<int> HttpPorts = new() { 80, 81, 82, 88, 3000, 5000, 5001, 7547, 8000, 8001, 8008, 8080, 8081, 8088, 8888, 8899, 9000, 37777, 49152 };

    public IEnumerable<DeviceAction> GetActions(Device d)
    {
        var ip = d.Ip?.ToString();
        if (ip == null) yield break;

        // Web: always offer 80/443, plus every open web-like port
        yield return new DeviceAction("Web", $"http://{ip}", () => Launcher.Open($"http://{ip}/"), "Open in browser");
        yield return new DeviceAction("Web", $"https://{ip}", () => Launcher.Open($"https://{ip}/"), "Open in browser (HTTPS)");
        foreach (var p in d.OpenPorts)
        {
            if (p is 80 or 443) continue;
            if (HttpsPorts.Contains(p)) yield return new DeviceAction("Web", $"https://{ip}:{p}", () => Launcher.Open($"https://{ip}:{p}/"));
            else if (HttpPorts.Contains(p)) yield return new DeviceAction("Web", $"http://{ip}:{p}", () => Launcher.Open($"http://{ip}:{p}/"));
        }
        if (d.Info.TryGetValue("UPnP description URL", out var loc))
            yield return new DeviceAction("Web", "UPnP description", () => Launcher.Open(loc), loc);

        // Remote access
        if (d.OpenPorts.Contains(22)) yield return new DeviceAction("Remote", "SSH", () => Launcher.Console($"ssh {ip}"));
        if (d.OpenPorts.Contains(23)) yield return new DeviceAction("Remote", "Telnet", () => Launcher.Console($"telnet {ip}"));
        if (d.OpenPorts.Contains(3389)) yield return new DeviceAction("Remote", "Remote Desktop", () => Launcher.Run("mstsc.exe", $"/v:{ip}"));
        if (d.OpenPorts.Contains(445) || d.OpenPorts.Contains(139)) yield return new DeviceAction("Remote", "Shared folders", () => Launcher.Open($@"\\{ip}"));
        if (d.OpenPorts.Contains(21)) yield return new DeviceAction("Remote", "FTP", () => Launcher.Open($"ftp://{ip}/"));
        if (d.OpenPorts.Contains(5900)) yield return new DeviceAction("Remote", "VNC", () => Launcher.Open($"vnc://{ip}"));
        if (d.OpenPorts.Contains(554)) yield return new DeviceAction("Remote", "RTSP stream", () => Launcher.Open($"rtsp://{ip}:554/"), "Opens in VLC or your default player");
        if (d.OpenPorts.Contains(8728)) yield return new DeviceAction("Remote", "MikroTik Winbox", () => Launcher.Open($"winbox://{ip}"));

        // Tools
        yield return new DeviceAction("Tools", "Ping", () => Launcher.Console($"ping -t {ip}"));
        yield return new DeviceAction("Tools", "Traceroute", () => Launcher.Console($"tracert -d {ip}"));
    }
}
