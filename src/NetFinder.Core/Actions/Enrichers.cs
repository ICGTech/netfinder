using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using NetFinder.Core.Model;
using NetFinder.Core.Plugins;

namespace NetFinder.Core.Actions;

/// <summary>Reads the &lt;title&gt; and Server header of every open web port.</summary>
public sealed partial class WebTitleEnricher : IDeviceEnricher
{
    public string Name => "Web title";
    private static readonly int[] Tls = { 443, 8443, 4443, 9443, 10443 };
    private static readonly int[] Plain = { 80, 81, 82, 88, 3000, 5000, 5001, 8000, 8001, 8008, 8080, 8081, 8088, 8888, 8899, 9000 };

    private static readonly HttpClient Http = new(new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true, // devices use self-signed certs
        AllowAutoRedirect = true,
        UseProxy = false,
    }) { Timeout = TimeSpan.FromSeconds(4) };

    public async Task EnrichAsync(Device device, EnrichContext ctx, CancellationToken ct)
    {
        IPAddress? ip; int[] ports;
        lock (device) { ip = device.Ip; ports = device.OpenPorts.Where(p => Tls.Contains(p) || Plain.Contains(p)).ToArray(); }
        if (ip == null) return;
        await Task.WhenAll(ports.Select(async p =>
        {
            var url = $"{(Tls.Contains(p) ? "https" : "http")}://{ip}:{p}/";
            try
            {
                using var resp = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
                var server = resp.Headers.Server.ToString();
                // Basic/Digest login realm often names the product ("TP-LINK Wireless N Router WR840N")
                var realm = resp.Headers.WwwAuthenticate.Select(h => h.Parameter ?? "").Select(pr => Regex.Match(pr, "realm=\"([^\"]{2,80})\"", RegexOptions.IgnoreCase))
                    .Where(m2 => m2.Success).Select(m2 => m2.Groups[1].Value).FirstOrDefault();
                var body = await ReadSome(resp, ct);
                var m = TitleRx().Match(body);
                var title = m.Success ? WebUtility.HtmlDecode(m.Groups[1].Value).Trim() : null;
                var info = string.Join("  ·  ", new[] { title, string.IsNullOrEmpty(server) ? null : server, $"HTTP {(int)resp.StatusCode}" }.Where(s => !string.IsNullOrEmpty(s)));
                ctx.Engine.Store.Touch(device, d =>
                {
                    d.PortInfo[p] = info;
                    if (!string.IsNullOrEmpty(title) && title.Length < 60) d.Info["Web page title"] = title;
                    if (!string.IsNullOrEmpty(server)) d.Info["Web server"] = server;
                    if (realm != null) d.Info["Web login realm"] = realm;
                });
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { }
        }));
    }

    private static async Task<string> ReadSome(HttpResponseMessage resp, CancellationToken ct)
    {
        await using var s = await resp.Content.ReadAsStreamAsync(ct);
        var buf = new byte[32768];
        var n = 0;
        int r;
        while (n < buf.Length && (r = await s.ReadAsync(buf.AsMemory(n), ct)) > 0) n += r;
        return Encoding.UTF8.GetString(buf, 0, n);
    }

    [GeneratedRegex(@"<title[^>]*>([^<]{1,200})</title>", RegexOptions.IgnoreCase)]
    private static partial Regex TitleRx();
}

/// <summary>Reverse DNS + NetBIOS name for devices we can reach.</summary>
public sealed class NameEnricher : IDeviceEnricher
{
    public string Name => "Names";

    public async Task EnrichAsync(Device device, EnrichContext ctx, CancellationToken ct)
    {
        IPAddress? ip; string? host;
        lock (device) { ip = device.Ip; host = device.Hostname; }
        if (ip == null) return;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(2000);
            var e = await Dns.GetHostEntryAsync(ip.ToString(), cts.Token);
            if (!string.IsNullOrEmpty(e.HostName) && e.HostName != ip.ToString())
                ctx.Engine.Store.Touch(device, d => { d.Info["DNS name"] = e.HostName; d.Hostname ??= e.HostName; });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }

        if (host != null) return;
        try
        {
            using var udp = new UdpClient(0);
            var q = Scanners.DiscoveryQueries.NbnsWildcardStatus();
            q[2] = 0; q[3] = 0; // unicast
            await udp.SendAsync(q, new IPEndPoint(ip, 137), ct);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(1500);
            var res = await udp.ReceiveAsync(cts.Token);
            var name = ParseNodeStatus(res.Buffer, out var group);
            if (name != null)
                ctx.Engine.Store.Touch(device, d =>
                {
                    d.Info["NetBIOS name"] = name; d.Hostname ??= name;
                    if (group != null) d.Info["Workgroup / domain"] = group;
                });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }
    }

    private static string? ParseNodeStatus(byte[] b, out string? group)
    {
        group = null;
        // header 12, name 34, type/class 4, ttl 4, rdlength 2, then count
        var off = 12 + 34 + 4 + 4 + 2;
        if (b.Length <= off) return null;
        int count = b[off++];
        string? name = null;
        for (var i = 0; i < count && off + 18 <= b.Length; i++, off += 18)
        {
            var n = Encoding.ASCII.GetString(b, off, 15).Trim();
            var suffix = b[off + 15];
            var isGroup = (b[off + 16] & 0x80) != 0;
            if (suffix == 0 && !isGroup) name ??= n;
            if (suffix == 0 && isGroup) group ??= n;
        }
        return name;
    }
}
