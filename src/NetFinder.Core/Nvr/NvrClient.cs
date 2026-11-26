using System.Net;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using NetFinder.Core.Model;
using NetFinder.Core.Net;

namespace NetFinder.Core.Nvr;

public enum NvrBrand { Auto, Hikvision, Dahua }

/// <summary>One camera (channel) reported by an NVR / DVR.</summary>
public sealed class NvrCamera
{
    public int Channel { get; init; }
    public string Name { get; set; } = "";
    /// <summary>Null for analog (DVR) channels.</summary>
    public string? Ip { get; init; }
    public int? Port { get; init; }
    public string? Model { get; init; }
    public string? Serial { get; init; }
    public string? Mac { get; init; }
    public string? Firmware { get; init; }
    public string? Protocol { get; init; }
    public bool? Online { get; set; }
    public string Status { get; set; } = "";
}

public sealed class NvrResult
{
    public NvrBrand Brand { get; init; }
    public string BrandName => Brand == NvrBrand.Dahua ? "Dahua" : "Hikvision";
    public string? Name { get; set; }
    public string? Model { get; set; }
    public string? Serial { get; set; }
    public string? Firmware { get; set; }
    public List<NvrCamera> Cameras { get; } = new();
    /// <summary>Things that could not be read (shown under the list).</summary>
    public List<string> Notes { get; } = new();
}

public sealed class NvrException : Exception
{
    public NvrException(string message, bool wrongPassword = false, Exception? inner = null) : base(message, inner) => WrongPassword = wrongPassword;
    public bool WrongPassword { get; }
}

/// <summary>
/// Reads the list of cameras connected to an NVR/DVR over its web API.
/// Hikvision (and rebrands: HiLook, Annke, LTS…): ISAPI. Dahua (and rebrands: Amcrest, Imou, Lorex, CP Plus…): CGI.
/// Stops at the first rejected login, because these recorders lock the account after a few wrong passwords.
/// The password is only kept in memory for the duration of the call.
/// </summary>
public static class NvrClient
{
    public static async Task<NvrResult> ReadAsync(Uri baseUri, string user, string password, NvrBrand brand, CancellationToken ct)
    {
        baseUri = new Uri(baseUri.GetLeftPart(UriPartial.Authority) + "/");
        if (brand == NvrBrand.Auto) brand = await DetectAsync(baseUri, ct);
        using var http = CreateClient(new NetworkCredential(user, password));
        try
        {
            return brand == NvrBrand.Dahua ? await ReadDahuaAsync(http, baseUri, ct) : await ReadHikvisionAsync(http, baseUri, ct);
        }
        catch (HttpRequestException ex) { throw new NvrException($"Could not connect to {baseUri.Authority}: {ex.Message}", inner: ex); }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested) { throw new NvrException($"{baseUri.Authority} did not answer in time.", inner: ex); }
    }

    /// <summary>Asks both APIs WITHOUT a password (does not count as a failed login) and looks at who answers.</summary>
    public static async Task<NvrBrand> DetectAsync(Uri baseUri, CancellationToken ct)
    {
        using var http = CreateClient(null);
        async Task<(int Status, string Realm, string Body)> Probe(string path)
        {
            try
            {
                using var r = await http.GetAsync(new Uri(baseUri, path), ct);
                var realm = r.Headers.WwwAuthenticate.Select(h => h.Parameter ?? "").FirstOrDefault() ?? "";
                var body = (int)r.StatusCode == 200 ? await r.Content.ReadAsStringAsync(ct) : "";
                return ((int)r.StatusCode, realm, body);
            }
            catch (HttpRequestException ex) { throw new NvrException($"Could not connect to {baseUri.Authority}: {ex.Message}\n\nCheck the address and the web port of the NVR (usually 80).", inner: ex); }
            catch (TaskCanceledException ex) when (!ct.IsCancellationRequested) { throw new NvrException($"{baseUri.Authority} did not answer in time.", inner: ex); }
        }
        var hik = await Probe("ISAPI/System/deviceInfo");
        var dah = await Probe("cgi-bin/magicBox.cgi?action=getDeviceType");
        bool isHik = hik.Status == 401 || (hik.Status == 200 && hik.Body.Contains("DeviceInfo", StringComparison.OrdinalIgnoreCase));
        bool isDah = dah.Status == 401 || (dah.Status == 200 && dah.Body.Contains("type=", StringComparison.OrdinalIgnoreCase));
        if (isHik && isDah) return dah.Realm.Contains("Login to", StringComparison.OrdinalIgnoreCase) ? NvrBrand.Dahua : NvrBrand.Hikvision;
        if (isHik) return NvrBrand.Hikvision;
        if (isDah) return NvrBrand.Dahua;
        throw new NvrException($"{baseUri.Authority} does not answer like a Hikvision or Dahua NVR/DVR (HTTP {hik.Status} / {dah.Status}).\n\n" +
                               "Check that this is the NVR's web address and port, or choose the brand by hand.");
    }

    private static HttpClient CreateClient(NetworkCredential? cred)
    {
        var h = new HttpClientHandler
        {
            Credentials = cred, // Basic or Digest, whichever the recorder asks for
            PreAuthenticate = false,
            UseProxy = false, // LAN device: never through the PC's web proxy
            // Recorders ship self-signed certificates; this client only talks to the address the user typed.
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
        };
        var http = new HttpClient(h) { Timeout = TimeSpan.FromSeconds(10) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"{AppInfo.Name}/{AppInfo.Version}");
        return http;
    }

    /// <summary>GET; null on 404/400/501 (feature not on this model). Throws on a rejected login.</summary>
    private static async Task<string?> GetAsync(HttpClient http, Uri baseUri, string path, CancellationToken ct, bool required = false)
    {
        using var r = await http.GetAsync(new Uri(baseUri, path), ct);
        var code = (int)r.StatusCode;
        if (code == 401)
            throw new NvrException("The NVR rejected the user name or password.\n\nCareful: after a few wrong tries the NVR locks this user for a while (often 30 minutes).", wrongPassword: true);
        if (code == 403)
            throw new NvrException("This user is not allowed to read the camera list. Log in with the admin user.");
        if (code >= 200 && code < 300) return await r.Content.ReadAsStringAsync(ct);
        if (required) throw new NvrException($"The NVR answered HTTP {code} for {path}.");
        return null;
    }

    // ───────────────────────────── Hikvision ISAPI ─────────────────────────────

    private static async Task<NvrResult> ReadHikvisionAsync(HttpClient http, Uri b, CancellationToken ct)
    {
        var res = new NvrResult { Brand = NvrBrand.Hikvision };
        var info = await GetAsync(http, b, "ISAPI/System/deviceInfo", ct, required: true);
        var di = ParseXml(info);
        if (di != null)
        {
            res.Name = Val(di.Root, "deviceName");
            res.Model = Val(di.Root, "model");
            res.Serial = Val(di.Root, "serialNumber");
            res.Firmware = Val(di.Root, "firmwareVersion");
        }

        var chans = ParseXml(await GetAsync(http, b, "ISAPI/ContentMgmt/InputProxy/channels", ct));
        if (chans != null)
            foreach (var c in chans.Descendants().Where(e => e.Name.LocalName == "InputProxyChannel"))
                res.Cameras.Add(ParseHikChannel(c));

        if (res.Cameras.Count > 0)
        {
            var st = ParseXml(await GetAsync(http, b, "ISAPI/ContentMgmt/InputProxy/channels/status", ct));
            if (st != null)
                foreach (var s in st.Descendants().Where(e => e.Name.LocalName == "InputProxyChannelStatus"))
                {
                    if (!int.TryParse(Val(s, "id"), out var id)) continue;
                    var cam = res.Cameras.FirstOrDefault(x => x.Channel == id);
                    if (cam == null) continue;
                    var online = Val(s, "online");
                    var detect = Val(s, "chanDetectResult");
                    cam.Online = online == null ? null : online.Equals("true", StringComparison.OrdinalIgnoreCase);
                    cam.Status = cam.Online switch { true => "Online", false => "Offline", _ => "" };
                    if (!string.IsNullOrEmpty(detect) && cam.Online != true) cam.Status = (cam.Status + " (" + HikDetect(detect) + ")").Trim();
                }
            else res.Notes.Add("Online/offline status could not be read.");
        }
        else
        {
            // DVR with analog channels (no IPs), or an NVR with no camera added yet
            var analog = ParseXml(await GetAsync(http, b, "ISAPI/System/Video/inputs/channels", ct));
            if (analog != null)
                foreach (var c in analog.Descendants().Where(e => e.Name.LocalName == "VideoInputChannel"))
                {
                    int.TryParse(Val(c, "id"), out var id);
                    var en = Val(c, "videoInputEnabled");
                    res.Cameras.Add(new NvrCamera
                    {
                        Channel = id, Name = Val(c, "name") ?? $"Camera {id}", Protocol = "Analog",
                        Model = Val(c, "resDesc") is { Length: > 0 } rd && rd != "NO VIDEO" ? "Analog " + rd : null,
                        Online = Val(c, "resDesc") == "NO VIDEO" ? false : en == null ? null : en == "true",
                        Status = Val(c, "resDesc") == "NO VIDEO" ? "No video" : en == "false" ? "Disabled" : "Analog",
                    });
                }
            if (res.Cameras.Count == 0) res.Notes.Add("The recorder reports no cameras (none added yet).");
        }
        return res;
    }

    internal static NvrCamera ParseHikChannel(XElement c)
    {
        int.TryParse(Val(c, "id"), out var id);
        var src = c.Elements().FirstOrDefault(e => e.Name.LocalName == "sourceInputPortDescriptor") ?? c;
        var ip = Val(src, "ipAddress") ?? Val(src, "ipV4Address") ?? Val(src, "hostName");
        int? port = int.TryParse(Val(src, "managePortNo"), out var p) ? p : null;
        return new NvrCamera
        {
            Channel = id,
            Name = Val(c, "name") ?? $"Camera {id}",
            Ip = string.IsNullOrWhiteSpace(ip) || ip == "0.0.0.0" ? null : ip.Trim(),
            Port = port,
            Model = Val(src, "model"),
            Serial = Val(src, "serialNumberEx") ?? Val(src, "serialNumber"),
            Mac = Val(src, "macAddress"),
            Firmware = Val(src, "firmwareVersionEx") ?? Val(src, "firmwareVersion"),
            Protocol = Val(src, "proxyProtocol"),
        };
    }

    private static string HikDetect(string s) => s switch
    {
        "connect" => "connected",
        "notConnect" or "netUnreachable" or "offline" => "not reachable",
        "passwordError" or "userNameOrPasswordError" => "wrong camera password",
        "ipcStreamFail" or "streamException" => "no video stream",
        "ipConflict" => "IP conflict",
        "notExist" => "camera not found",
        "lackOfBandwidth" or "bandwidthExceeded" => "not enough bandwidth",
        _ => Regex.Replace(s, "(?<=[a-z])(?=[A-Z])", " ").ToLowerInvariant(),
    };

    private static XDocument? ParseXml(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        try { return XDocument.Parse(text); } catch { return null; }
    }

    /// <summary>Text of the first direct child with that local name (ignores the ISAPI XML namespace).</summary>
    private static string? Val(XElement? e, string name)
    {
        var v = e?.Elements().FirstOrDefault(x => x.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;
        return string.IsNullOrWhiteSpace(v) ? null : v.Trim();
    }

    // ───────────────────────────── Dahua CGI ─────────────────────────────

    private static async Task<NvrResult> ReadDahuaAsync(HttpClient http, Uri b, CancellationToken ct)
    {
        var res = new NvrResult { Brand = NvrBrand.Dahua };
        var type = KeyValues(await GetAsync(http, b, "cgi-bin/magicBox.cgi?action=getDeviceType", ct, required: true));
        res.Model = type.GetValueOrDefault("type");
        res.Serial = KeyValues(await GetAsync(http, b, "cgi-bin/magicBox.cgi?action=getSerialNo", ct)).GetValueOrDefault("sn");
        res.Name = KeyValues(await GetAsync(http, b, "cgi-bin/magicBox.cgi?action=getMachineName", ct)).GetValueOrDefault("name");
        var sw = KeyValues(await GetAsync(http, b, "cgi-bin/magicBox.cgi?action=getSoftwareVersion", ct)).GetValueOrDefault("version");
        res.Firmware = sw;

        var remote = await GetAsync(http, b, "cgi-bin/configManager.cgi?action=getConfig&name=RemoteDevice", ct);
        var channels = await GetAsync(http, b, "cgi-bin/configManager.cgi?action=getConfig&name=RemoteChannel", ct);
        var titles = await GetAsync(http, b, "cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle", ct);
        res.Cameras.AddRange(ParseDahua(remote, channels, titles));
        if (remote == null) res.Notes.Add("The recorder did not give its list of IP cameras (an analog DVR, or this user has no rights).");
        else if (res.Cameras.Count == 0) res.Notes.Add("The recorder reports no IP cameras (none added yet).");

        if (res.Cameras.Count > 0)
        {
            var state = await GetAsync(http, b, "cgi-bin/LogicDeviceManager.cgi?action=getCameraState&uniqueChannels[0]=-1", ct);
            if (state != null) ApplyDahuaState(res.Cameras, state);
            else res.Notes.Add("Online/offline status could not be read.");
        }
        return res;
    }

    /// <summary>Parses "key=value" lines.</summary>
    internal static Dictionary<string, string> KeyValues(string? text)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (text == null) return d;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var i = line.IndexOf('=');
            if (i > 0) d[line[..i].Trim()] = line[(i + 1)..].Trim();
        }
        return d;
    }

    private static readonly Regex RemoteLine = new(@"^table\.RemoteDevice\.(?<id>[^.]+)\.(?<field>.+)$", RegexOptions.Compiled);
    private static readonly Regex ChannelLine = new(@"^table\.RemoteChannel\[(?<n>\d+)\]\.(?<field>\w+)$", RegexOptions.Compiled);
    private static readonly Regex TitleLine = new(@"^table\.ChannelTitle\[(?<n>\d+)\]\.Name$", RegexOptions.Compiled);

    internal static List<NvrCamera> ParseDahua(string? remoteDevice, string? remoteChannel, string? channelTitle)
    {
        var devs = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();
        foreach (var (k, v) in KeyValues(remoteDevice))
        {
            var m = RemoteLine.Match(k);
            if (!m.Success) continue;
            var id = m.Groups["id"].Value;
            if (!devs.TryGetValue(id, out var f)) { devs[id] = f = new(StringComparer.OrdinalIgnoreCase); order.Add(id); }
            f[m.Groups["field"].Value] = v;
        }

        // RemoteChannel[n].Device = which remote device feeds channel n+1
        var chanOf = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var chanEnabled = new Dictionary<int, bool>();
        foreach (var (k, v) in KeyValues(remoteChannel))
        {
            var m = ChannelLine.Match(k);
            if (!m.Success) continue;
            var n = int.Parse(m.Groups["n"].Value);
            if (m.Groups["field"].Value.Equals("Device", StringComparison.OrdinalIgnoreCase) && v.Length > 0) chanOf.TryAdd(v, n + 1);
            if (m.Groups["field"].Value.Equals("Enable", StringComparison.OrdinalIgnoreCase)) chanEnabled[n + 1] = v.Equals("true", StringComparison.OrdinalIgnoreCase);
        }
        var title = new Dictionary<int, string>();
        foreach (var (k, v) in KeyValues(channelTitle))
        {
            var m = TitleLine.Match(k);
            if (m.Success && v.Length > 0) title[int.Parse(m.Groups["n"].Value) + 1] = v;
        }

        var list = new List<NvrCamera>();
        foreach (var id in order)
        {
            var f = devs[id];
            var addr = f.GetValueOrDefault("Address")?.Trim();
            if (string.IsNullOrEmpty(addr) || addr == "0.0.0.0") continue;
            if (f.GetValueOrDefault("Enable")?.Equals("false", StringComparison.OrdinalIgnoreCase) == true) continue;
            int ch;
            if (!chanOf.TryGetValue(id, out ch))
            {
                var n = Regex.Match(id, @"(\d+)$");
                ch = n.Success ? int.Parse(n.Groups[1].Value) + 1 : list.Count + 1;
            }
            var name = title.GetValueOrDefault(ch) ?? f.GetValueOrDefault("Name") ?? f.GetValueOrDefault("VideoInputs[0].Name");
            list.Add(new NvrCamera
            {
                Channel = ch,
                Name = string.IsNullOrWhiteSpace(name) ? $"Camera {ch}" : name,
                Ip = addr,
                Port = int.TryParse(f.GetValueOrDefault("HttpPort") ?? f.GetValueOrDefault("Port"), out var p) ? p : null,
                Model = f.GetValueOrDefault("DeviceType") is { Length: > 0 } dt ? dt : null,
                Serial = f.GetValueOrDefault("SerialNo") is { Length: > 0 } sn ? sn : null,
                Mac = f.GetValueOrDefault("Mac") is { Length: > 0 } mac ? mac : null,
                Firmware = f.GetValueOrDefault("Version") is { Length: > 0 } ver ? ver : null,
                Protocol = f.GetValueOrDefault("ProtocolType"),
                Status = chanEnabled.TryGetValue(ch, out var en) && !en ? "Disabled" : "",
            });
        }
        return list.OrderBy(c => c.Channel).ToList();
    }

    private static readonly Regex StateLine = new(@"^states\[(?<n>\d+)\]\.(?<field>\w+)$", RegexOptions.Compiled);

    internal static void ApplyDahuaState(List<NvrCamera> cams, string text)
    {
        var chan = new Dictionary<int, int>();
        var state = new Dictionary<int, string>();
        foreach (var (k, v) in KeyValues(text))
        {
            var m = StateLine.Match(k);
            if (!m.Success) continue;
            var n = int.Parse(m.Groups["n"].Value);
            if (m.Groups["field"].Value.Equals("channel", StringComparison.OrdinalIgnoreCase) && int.TryParse(v, out var c)) chan[n] = c + 1;
            if (m.Groups["field"].Value.Equals("connectionState", StringComparison.OrdinalIgnoreCase)) state[n] = v;
        }
        foreach (var (n, s) in state)
        {
            var ch = chan.TryGetValue(n, out var c) ? c : n + 1;
            var cam = cams.FirstOrDefault(x => x.Channel == ch);
            if (cam == null) continue;
            cam.Online = s.Equals("Connected", StringComparison.OrdinalIgnoreCase);
            cam.Status = cam.Online == true ? "Online" : s.Equals("Connecting", StringComparison.OrdinalIgnoreCase) ? "Connecting" : "Offline";
        }
    }

    // ───────────────────────────── into the main list ─────────────────────────────

    /// <summary>
    /// Adds the cameras to the device list. A camera that was not found directly (it sits on the NVR's own
    /// camera network, e.g. the NVR's PoE ports) is marked "behind NVR" instead of "reachable".
    /// </summary>
    public static int AddToStore(DeviceStore store, Device nvr, NvrResult r)
    {
        var nvrIp = nvr.Ip?.ToString() ?? "";
        store.Touch(nvr, d =>
        {
            d.Info["NVR cameras"] = r.Cameras.Count.ToString();
            d.Info["NVR brand (API)"] = r.BrandName;
            if (r.Model != null) { d.Info["NVR model"] = r.Model; d.Model ??= r.Model; }
            if (r.Serial != null) d.Info["NVR serial number"] = r.Serial;
            if (r.Firmware != null) d.Info["NVR firmware"] = r.Firmware;
            if (r.Name != null) d.Hostname ??= r.Name;
        });
        var added = 0;
        foreach (var cam in r.Cameras)
        {
            if (cam.Ip == null || !IPAddress.TryParse(cam.Ip, out var ip) || !Ip4.IsUsableHost(ip) || cam.Ip == nvrIp) continue;
            store.ObserveIp(ip, "NVR", null, d =>
            {
                d.BehindNvr = nvrIp;
                // Seen only through the NVR (never answered us): not reachable from this PC.
                if (d.Mac.Length == 0 && !d.Sources.Contains("Ping") && !d.Sources.Contains("TCP")) d.Routed = false;
                d.Info["NVR channel"] = $"{nvrIp}  channel {cam.Channel}";
                if (cam.Name.Length > 0) { d.Info["Name on NVR"] = cam.Name; d.Hostname ??= cam.Name; }
                if (cam.Model != null) d.Model ??= cam.Model;
                if (cam.Serial != null) d.Info["Serial number"] = cam.Serial;
                if (cam.Firmware != null) d.Info["Firmware"] = cam.Firmware;
                if (cam.Port != null) d.Info["Port on NVR"] = cam.Port.ToString()!;
                if (cam.Protocol != null) d.Info["Protocol on NVR"] = cam.Protocol;
                if (cam.Status.Length > 0) d.Info["Status on NVR"] = cam.Status;
                if (cam.Mac != null && DeviceStore.IsValidMac(cam.Mac.ToUpperInvariant().Replace('-', ':')))
                {
                    var mac = cam.Mac.ToUpperInvariant().Replace('-', ':');
                    d.Info["MAC (from NVR)"] = mac;
                    d.Vendor ??= OuiLookup.Lookup(mac);
                }
                d.Vendor ??= cam.Protocol?.Equals("HIKVISION", StringComparison.OrdinalIgnoreCase) == true ? "Hikvision" :
                             r.Brand == NvrBrand.Dahua && cam.Protocol?.Equals("Private", StringComparison.OrdinalIgnoreCase) == true ? "Dahua" : null;
            });
            added++;
        }
        return added;
    }
}
