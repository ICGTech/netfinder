using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace NetFinder.Core.Net;

/// <summary>What an ONVIF camera / NVR says about itself in a WS-Discovery ProbeMatch (no password needed).</summary>
public sealed record OnvifInfo(IPAddress From, string? Hardware, string? Name, string? Location, string? Mac, string Types, string XAddrs);

/// <summary>
/// WS-Discovery (UDP 3702): the "Probe" ONVIF tools send to find cameras. Answers carry scopes like
/// onvif://www.onvif.org/hardware/DS-2CD2143G0-I and onvif://www.onvif.org/name/HIKVISION.
/// </summary>
public static partial class WsDiscovery
{
    public static readonly IPEndPoint Multicast = new(IPAddress.Parse("239.255.255.250"), 3702);

    public static byte[] Probe(bool videoOnly) => Encoding.UTF8.GetBytes(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
        "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">" +
        $"<e:Header><w:MessageID>uuid:{Guid.NewGuid()}</w:MessageID><w:To e:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>" +
        "<w:Action e:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>" +
        (videoOnly ? "<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>" : "<e:Body><d:Probe/></e:Body>") +
        "</e:Envelope>");

    /// <summary>Asks one IP directly (works across subnets when the IP is reachable).</summary>
    public static async Task<OnvifInfo?> ProbeAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        using var udp = new UdpClient(0);
        var found = await ProbeCoreAsync(udp, new IPEndPoint(ip, 3702), timeoutMs, ct, from => from.Equals(ip));
        return found.FirstOrDefault();
    }

    /// <summary>Multicast probe from one local address; collects every answer for <paramref name="timeoutMs"/>.</summary>
    public static async Task<List<OnvifInfo>> ProbeAllAsync(IPAddress localIp, int timeoutMs, CancellationToken ct)
    {
        using var udp = new UdpClient(new IPEndPoint(localIp, 0));
        // Windows: don't let one ICMP "port unreachable" abort collecting the other answers
        if (OperatingSystem.IsWindows()) try { udp.Client.IOControl(-1744830452 /* SIO_UDP_CONNRESET */, new byte[] { 0, 0, 0, 0 }, null); } catch { }
        udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 2);
        try { udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, localIp.GetAddressBytes()); } catch { }
        return await ProbeCoreAsync(udp, Multicast, timeoutMs, ct, _ => true);
    }

    private static async Task<List<OnvifInfo>> ProbeCoreAsync(UdpClient udp, IPEndPoint to, int timeoutMs, CancellationToken ct, Func<IPAddress, bool> accept)
    {
        var res = new Dictionary<IPAddress, OnvifInfo>();
        await udp.SendAsync(Probe(videoOnly: true), to, ct);
        await udp.SendAsync(Probe(videoOnly: false), to, ct);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            while (true)
            {
                var r = await udp.ReceiveAsync(cts.Token);
                if (!accept(r.RemoteEndPoint.Address)) continue;
                var info = Parse(r.RemoteEndPoint.Address, Encoding.UTF8.GetString(r.Buffer));
                if (info == null) continue;
                // keep the richest answer per device
                if (!res.TryGetValue(info.From, out var old) || (old.Hardware == null && info.Hardware != null)) res[info.From] = info;
                if (to.Port == 3702 && !to.Address.Equals(Multicast.Address) && info.Hardware != null) break;
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        catch (SocketException) { } // ICMP "port unreachable" (Windows reports it on receive): nothing listens on 3702
        return res.Values.ToList();
    }

    [GeneratedRegex(@"<(?:\w+:)?Scopes[^>]*>([^<]*)</(?:\w+:)?Scopes>", RegexOptions.IgnoreCase)]
    private static partial Regex ScopesRx();
    [GeneratedRegex(@"<(?:\w+:)?Types[^>]*>([^<]*)</(?:\w+:)?Types>", RegexOptions.IgnoreCase)]
    private static partial Regex TypesRx();
    [GeneratedRegex(@"<(?:\w+:)?XAddrs[^>]*>([^<]*)</(?:\w+:)?XAddrs>", RegexOptions.IgnoreCase)]
    private static partial Regex XAddrsRx();

    internal static OnvifInfo? Parse(IPAddress from, string xml)
    {
        if (!xml.Contains("ProbeMatch", StringComparison.OrdinalIgnoreCase)) return null;
        var scopes = ScopesRx().Match(xml) is { Success: true } s ? s.Groups[1].Value : "";
        string? Scope(string key)
        {
            foreach (var sc in scopes.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            {
                var prefix = "onvif://www.onvif.org/" + key + "/";
                if (sc.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    var v = Uri.UnescapeDataString(sc[prefix.Length..]).Replace('_', ' ').Trim();
                    if (v.Length > 0) return v;
                }
            }
            return null;
        }
        var types = TypesRx().Match(xml) is { Success: true } t ? t.Groups[1].Value.Trim() : "";
        var xaddrs = XAddrsRx().Match(xml) is { Success: true } x ? x.Groups[1].Value.Trim() : "";
        return new OnvifInfo(from, Scope("hardware"), Scope("name"), Scope("location"), Scope("MAC"), types, xaddrs);
    }
}
