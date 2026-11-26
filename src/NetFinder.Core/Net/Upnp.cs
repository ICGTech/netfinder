using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;

namespace NetFinder.Core.Net;

public sealed record UpnpDescription(string? FriendlyName, string? Manufacturer, string? ModelName, string? ModelNumber, string? ModelDescription,
    string? SerialNumber, string? DeviceType, string? PresentationUrl)
{
    private static readonly System.Text.RegularExpressions.Regex SoftwareRx = new(
        @"windows media|media player|productagent|plex media|serviio|twonky|universal media server|kodi|vlc|jriver|foobar|emby|jellyfin|subsonic|^1-00-00$",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>"Archer C6 v2.0", "DS918+"… or null when the description has no useful model.</summary>
    public string? Model
    {
        get
        {
            var name = ModelName?.Trim();
            var number = ModelNumber?.Trim();
            // Software on a PC advertises itself, not the PC model: Windows media sharing, HP's "ProductAgent1.0 1-00-00"…
            if (SoftwareRx.IsMatch(name ?? "") || SoftwareRx.IsMatch(number ?? "")) return null;
            if (string.IsNullOrEmpty(name)) return string.IsNullOrEmpty(number) ? null : number;
            if (string.IsNullOrEmpty(number) || name.Contains(number, StringComparison.OrdinalIgnoreCase)) return name;
            if (number.Contains(name, StringComparison.OrdinalIgnoreCase)) return number.Length <= 40 ? number : name;
            return number.Length <= 20 ? $"{name} {number}" : name;
        }
    }
}

/// <summary>UPnP: the device description XML behind the SSDP "LOCATION" URL, and a unicast M-SEARCH to find that URL.</summary>
public static class Upnp
{
    private static readonly HttpClient Http = new(new HttpClientHandler { UseProxy = false, ServerCertificateCustomValidationCallback = (_, _, _, _) => true })
    { Timeout = TimeSpan.FromSeconds(4) };

    /// <summary>Asks one IP directly on UDP 1900 (UPnP 1.1 unicast search). Returns the LOCATION URLs it gave.</summary>
    public static async Task<List<string>> SearchAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        var res = new List<string>();
        using var udp = new UdpClient(0);
        var msg = Encoding.ASCII.GetBytes($"M-SEARCH * HTTP/1.1\r\nHOST: {ip}:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\nUSER-AGENT: {AppInfo.Name}/{AppInfo.Version} UPnP/1.1\r\n\r\n");
        var ep = new IPEndPoint(ip, 1900);
        await udp.SendAsync(msg, ep, ct);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            while (true)
            {
                var r = await udp.ReceiveAsync(cts.Token);
                if (!r.RemoteEndPoint.Address.Equals(ip)) continue;
                foreach (var line in Encoding.ASCII.GetString(r.Buffer).Split('\n'))
                {
                    var i = line.IndexOf(':');
                    if (i > 0 && line[..i].Trim().Equals("LOCATION", StringComparison.OrdinalIgnoreCase))
                    {
                        var loc = line[(i + 1)..].Trim();
                        if (!res.Contains(loc)) res.Add(loc);
                    }
                }
                if (res.Count > 0) break;
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        catch (SocketException) { } // ICMP "port unreachable": no UPnP there
        return res;
    }

    public static async Task<UpnpDescription?> GetDescriptionAsync(string url, CancellationToken ct)
    {
        try
        {
            var xml = await Http.GetStringAsync(url, ct);
            return Parse(xml);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    internal static UpnpDescription? Parse(string xml)
    {
        XDocument doc;
        try { doc = XDocument.Parse(xml); } catch { return null; }
        var dev = doc.Root?.Elements().FirstOrDefault(e => e.Name.LocalName == "device");
        if (dev == null) return null;
        string? V(string n) => dev.Elements().FirstOrDefault(e => e.Name.LocalName == n)?.Value is { } v && v.Trim().Length > 0 ? v.Trim() : null;
        return new UpnpDescription(V("friendlyName"), V("manufacturer"), V("modelName"), V("modelNumber"), V("modelDescription"),
            V("serialNumber"), V("deviceType"), V("presentationURL"));
    }
}
