using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using NetFinder.Core.Model;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetFinder.Core;

/// <summary>
/// The heart of the program: owns the adapters, the passive listener, the active scanners
/// and the device store. The UI only talks to this class.
/// </summary>
public sealed class NetworkEngine : IDisposable
{
    public DeviceStore Store { get; } = new();
    public Settings Settings { get; }
    public PluginRegistry Plugins { get; } = new();
    public List<Adapter> Adapters { get; } = new();

    /// <summary>True when Npcap (Windows) / libpcap is installed and usable.</summary>
    public bool CaptureAvailable { get; private set; }
    public string? CaptureError { get; private set; }
    /// <summary>"Npcap 1.79", "WinPcap 4.1.3", "libpcap 1.10" … or null without a capture driver.</summary>
    public string? CaptureDriver { get; private set; }
    /// <summary>True when the capture driver is old WinPcap (works badly on Wi-Fi, no Wi-Fi sending).</summary>
    public bool OldWinPcap => CaptureDriver?.Contains("WinPcap", StringComparison.OrdinalIgnoreCase) == true && !WindowsNet.NpcapInstalled;
    public bool Listening { get; private set; }

    /// <summary>Subnets that devices revealed passively (used by the "other subnet" probe).</summary>
    public ConcurrentDictionary<Subnet, string> LearnedSubnets { get; } = new();

    public event Action<string>? LogMessage;
    private readonly ConcurrentDictionary<string, object> _sendLocks = new();
    private readonly List<(LibPcapLiveDevice dev, Adapter adapter, PacketArrivalEventHandler handler)> _captures = new();

    public NetworkEngine(Settings settings, params Assembly[] pluginAssemblies)
    {
        Settings = settings;
        Store.BindAdapters(() => Adapters);
        var asms = new List<Assembly> { typeof(NetworkEngine).Assembly };
        asms.AddRange(pluginAssemblies);
        Plugins.LoadFrom(asms);
        foreach (var e in Plugins.LoadErrors) Log("Plugin load error: " + e);
        Store.Classifiers.AddRange(Plugins.Classifiers);
    }

    public void Log(string msg) => LogMessage?.Invoke($"{DateTime.Now:HH:mm:ss}  {msg}");

    // ───────────────────────────── adapters ─────────────────────────────

    public void LoadAdapters()
    {
        Adapters.Clear();
        try
        {
            var list = LibPcapLiveDeviceList.Instance;
            CaptureAvailable = true;
            try { CaptureDriver = ShortDriverName(Pcap.Version); } catch { CaptureDriver = "pcap"; }
            Log("Capture driver: " + CaptureDriver);
            foreach (var d in list)
            {
                if (d.Loopback || d.Name.Contains("Loopback", StringComparison.OrdinalIgnoreCase)) continue;
                var id = d.Name.Replace(@"\Device\NPF_", "", StringComparison.OrdinalIgnoreCase);
                var a = new Adapter { Id = id, PcapName = d.Name, PcapDevice = d, FriendlyName = d.Interface?.FriendlyName ?? d.Name, Description = d.Description ?? "" };
                if (d.MacAddress != null && d.MacAddress.GetAddressBytes().Length == 6) a.MacBytes = d.MacAddress.GetAddressBytes();
                a.RefreshFromOs();
                if (a.Addresses.Count == 0)
                {
                    foreach (var pa in d.Addresses)
                    {
                        var ip = pa.Addr?.ipAddress;
                        var mask = pa.Netmask?.ipAddress;
                        if (ip?.AddressFamily == AddressFamily.InterNetwork && mask != null)
                            a.Addresses.Add(new AdapterAddress(ip, PrefixFromMask(mask)));
                    }
                    a.IsUp = true;
                }
                if (a.MacBytes.All(b => b == 0)) continue; // not an Ethernet-like device (VPN tunnels etc.)
                Adapters.Add(a);
            }
        }
        catch (Exception ex)
        {
            CaptureAvailable = false;
            CaptureError = ex is TypeInitializationException or DllNotFoundException || ex.InnerException is DllNotFoundException
                ? "Npcap is not installed" : ex.Message;
            Log("Packet capture unavailable: " + CaptureError);
            LoadAdaptersWithoutPcap();
        }
        Adapters.Sort((x, y) => (y.IsUp && y.Addresses.Count > 0).CompareTo(x.IsUp && x.Addresses.Count > 0));
    }

    private static string ShortDriverName(string v)
    {
        // "Npcap version 1.79, based on libpcap version 1.10.4" -> "Npcap 1.79"
        var m = System.Text.RegularExpressions.Regex.Match(v, @"^(\w+) version ([\d.]+)");
        return m.Success ? $"{m.Groups[1].Value} {m.Groups[2].Value}" : v.Split(',')[0];
    }

    private void LoadAdaptersWithoutPcap()
    {
        foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.NetworkInterfaceType is System.Net.NetworkInformation.NetworkInterfaceType.Loopback or System.Net.NetworkInformation.NetworkInterfaceType.Tunnel) continue;
            var a = new Adapter { Id = ni.Id.Trim('{', '}'), PcapName = "" };
            a.RefreshFromOs();
            if (a.MacBytes.All(b => b == 0)) continue;
            Adapters.Add(a);
        }
    }

    public void RefreshAdapterAddresses()
    {
        foreach (var a in Adapters) a.RefreshFromOs();
        Store.RecomputeReachability();
    }

    private static int PrefixFromMask(IPAddress mask)
    {
        var v = Ip4.ToUInt(mask);
        var n = 0;
        while ((v & 0x80000000) != 0) { n++; v <<= 1; }
        return n;
    }

    public Adapter? AdapterById(string? id) => id == null ? null : Adapters.FirstOrDefault(a => a.Id == id);

    // ───────────────────────────── passive listening ─────────────────────────────

    /// <summary>BPF filter: only the traffic that reveals devices (broadcasts, multicasts, ARP, discovery replies).</summary>
    public const string CaptureFilter =
        "arp or ether broadcast or ether multicast or udp port 67 or udp port 68 or udp port 137 or udp port 138 or udp port 1900 or udp port 5353";

    public void StartListening(IEnumerable<Adapter> adapters)
    {
        StopListening();
        if (!CaptureAvailable) { StartRawListening(adapters); return; }
        foreach (var a in adapters)
        {
            if (a.PcapDevice is not LibPcapLiveDevice dev) continue;
            try
            {
                if (!dev.Opened) dev.Open(new DeviceConfiguration { Mode = DeviceModes.MaxResponsiveness, ReadTimeout = 200 });
                try { dev.Filter = CaptureFilter; } catch (Exception ex) { Log($"{a.FriendlyName}: filter not applied ({ex.Message}), capturing everything"); }
                var ctx = new CaptureContext { Adapter = a, Store = Store, Engine = this };
                PacketArrivalEventHandler h = (_, e) => OnPacket(e, ctx);
                dev.OnPacketArrival += h;
                dev.StartCapture();
                _captures.Add((dev, a, h));
                Log($"Listening on {a.FriendlyName} ({a.Mac})");
            }
            catch (Exception ex)
            {
                Log($"Cannot listen on {a.FriendlyName}: {ex.Message}");
            }
        }
        Listening = _captures.Count > 0;
    }

    // ── listening without Npcap: Windows raw socket (SIO_RCVALL). Sees IP broadcasts/multicasts
    //    (mDNS, SSDP, NetBIOS, DHCP…) from ANY subnet, but not ARP and not MAC addresses.
    private readonly List<(Socket Socket, CancellationTokenSource Cts)> _raw = new();

    private void StartRawListening(IEnumerable<Adapter> adapters)
    {
        if (!OperatingSystem.IsWindows()) return;
        foreach (var a in adapters)
        foreach (var addr in a.Addresses.ToList())
        {
            try
            {
                var sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                sock.Bind(new IPEndPoint(addr.Ip, 0));
                try { sock.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), new byte[4]); }        // RCVALL_ON
                catch { sock.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(3), new byte[4]); }       // RCVALL_IPLEVEL
                var cts = new CancellationTokenSource();
                _raw.Add((sock, cts));
                var ctx = new CaptureContext { Adapter = a, Store = Store, Engine = this };
                _ = Task.Run(() => RawLoop(sock, addr, ctx, cts.Token));
                Log($"Listening on {a.FriendlyName} ({addr.Ip}) without Npcap – broadcasts only, no ARP");
            }
            catch (Exception ex) { Log($"Cannot listen on {a.FriendlyName} without Npcap: {ex.Message}"); }
        }
        Listening = _raw.Count > 0;
    }

    private async Task RawLoop(Socket sock, AdapterAddress local, CaptureContext ctx, CancellationToken ct)
    {
        var buf = new byte[65535];
        var own = Ip4.ToUInt(local.Ip);
        var bcast = local.Subnet.Broadcast;
        while (!ct.IsCancellationRequested)
        {
            int n;
            try { n = await sock.ReceiveAsync(buf, SocketFlags.None, ct); }
            catch { if (ct.IsCancellationRequested) return; await Task.Delay(200); continue; }
            if (n < 20 || buf[0] >> 4 != 4) continue;
            var src = Ip4.ToUInt(buf.AsSpan(12, 4));
            var dst = Ip4.ToUInt(buf.AsSpan(16, 4));
            if (src == own || src == 0) continue;
            var multicast = dst >> 28 == 14;
            var broadcast = dst == uint.MaxValue || dst == bcast || ((dst & 0xff) == 0xff && !local.Subnet.Contains(dst));
            if (!multicast && !broadcast) continue; // unicast may come from the internet via the router – ignore
            var frame = new byte[14 + n];
            if (multicast) { frame[0] = 0x01; frame[1] = 0x00; frame[2] = 0x5e; frame[3] = (byte)((dst >> 16) & 0x7f); frame[4] = (byte)(dst >> 8); frame[5] = (byte)dst; }
            else for (var i = 0; i < 6; i++) frame[i] = 0xff;
            // source MAC stays 00:00:00:00:00:00 = unknown (DeviceStore.NoMac)
            frame[12] = 0x08; frame[13] = 0x00;
            Buffer.BlockCopy(buf, 0, frame, 14, n);
            var f = Frame.Parse(frame);
            if (f != null) ProcessFrame(f, ctx);
        }
    }

    public void StopListening()
    {
        foreach (var (sock, cts) in _raw) { cts.Cancel(); try { sock.Close(); } catch { } }
        _raw.Clear();
        foreach (var (dev, _, h) in _captures)
        {
            try { dev.StopCapture(); } catch { }
            dev.OnPacketArrival -= h;
        }
        _captures.Clear();
        Listening = false;
    }

    private void OnPacket(PacketCapture e, CaptureContext ctx)
    {
        try
        {
            var raw = e.GetPacket();
            var frame = Frame.Parse(raw.Data, raw.Timeval.Date.ToLocalTime());
            if (frame == null) return;
            ProcessFrame(frame, ctx);
        }
        catch (Exception ex) { Log("Packet error: " + ex.Message); }
    }

    /// <summary>Run all analyzers on one frame. Public so tests / offline pcap import can use it.</summary>
    public void ProcessFrame(Frame frame, CaptureContext ctx)
    {
        if (frame.SrcMac.Equals(ctx.Adapter.Mac, StringComparison.OrdinalIgnoreCase)) return; // our own traffic
        foreach (var an in Plugins.Analyzers)
        {
            try { an.Analyze(frame, ctx); }
            catch (Exception ex) { Log($"{an.Name}: {ex.Message}"); }
        }
    }

    public void LearnSubnet(Subnet s, string why)
    {
        if (Adapters.Any(a => a.Addresses.Any(x => x.Subnet.Overlaps(s)))) return;
        if (LearnedSubnets.TryAdd(s, why)) Log($"Learned subnet {s} ({why})");
    }

    // ───────────────────────────── sending ─────────────────────────────

    /// <summary>Open the adapter for sending if needed.</summary>
    private LibPcapLiveDevice? OpenForSend(Adapter a)
    {
        if (a.PcapDevice is not LibPcapLiveDevice dev) return null;
        if (!dev.Opened) dev.Open(new DeviceConfiguration { Mode = DeviceModes.MaxResponsiveness, ReadTimeout = 200 });
        return dev;
    }

    public bool SendFrame(Adapter a, byte[] frame)
    {
        var dev = OpenForSend(a);
        if (dev == null) return false;
        lock (_sendLocks.GetOrAdd(a.Id, _ => new object())) dev.SendPacket(frame);
        return true;
    }

    /// <summary>Send many frames at the configured rate.</summary>
    public async Task SendFramesAsync(Adapter a, IEnumerable<byte[]> frames, CancellationToken ct, Action<int>? onSent = null)
    {
        var fps = Math.Max(100, Settings.FramesPerSecond);
        var batch = Math.Max(1, fps / 50); // ~20 ms batches
        var n = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        foreach (var f in frames)
        {
            ct.ThrowIfCancellationRequested();
            try { SendFrame(a, f); } catch (Exception ex) { Log($"Send failed on {a.FriendlyName}: {ex.Message}"); return; }
            n++;
            if (n % batch == 0)
            {
                onSent?.Invoke(n);
                var due = n * 1000.0 / fps - sw.Elapsed.TotalMilliseconds;
                if (due > 1) await Task.Delay(TimeSpan.FromMilliseconds(due), ct);
            }
        }
        onSent?.Invoke(n);
    }

    // ───────────────────────────── scanning ─────────────────────────────

    public async Task ScanAsync(IReadOnlyList<Adapter> adapters, IEnumerable<IActiveScanner> scanners, IProgress<string> status, CancellationToken ct)
    {
        if (!IpRange.TryParseList(Settings.ScanRanges, out var ranges, out var err)) throw new ArgumentException(err);
        var ctx = new ScanContext { Engine = this, Adapters = adapters, Settings = Settings, Status = status, Ranges = ranges };
        foreach (var s in scanners)
        {
            if (s.RequiresCapture && !CaptureAvailable) { Log($"Skipping {s.Name} (needs Npcap)"); continue; }
            ct.ThrowIfCancellationRequested();
            status.Report(s.Name + "…");
            try { await s.RunAsync(ctx, ct); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { Log($"{s.Name} failed: {ex.Message}"); }
        }
        status.Report("Waiting for late replies…");
        await Task.Delay(1500, ct);
        foreach (var (mac, count) in Store.SuppressProxyArp())
            Log($"{mac} answered ARP for {count} addresses in other subnets (router doing proxy ARP) – ignored those answers");
    }

    // ───────────────────────────── ports & enrichment ─────────────────────────────

    public async Task CheckPortsAsync(Device device, CancellationToken ct, IEnumerable<int>? ports = null)
    {
        IPAddress? ip;
        lock (device) ip = device.Ip;
        if (ip == null) return;
        var list = (ports ?? Settings.Ports).Distinct().ToList();
        var open = new ConcurrentBag<int>();
        using var sem = new SemaphoreSlim(48);
        await Task.WhenAll(list.Select(async p =>
        {
            await sem.WaitAsync(ct);
            try { if (await IsTcpOpenAsync(ip, p, Settings.PortTimeoutMs, ct)) open.Add(p); }
            finally { sem.Release(); }
        }));
        Store.Touch(device, d =>
        {
            foreach (var p in list) if (!open.Contains(p)) d.OpenPorts.Remove(p);
            foreach (var p in open) d.OpenPorts.Add(p);
            d.PortsCheckedAt = DateTime.Now;
        });
        var ectx = new EnrichContext { Engine = this, Settings = Settings };
        foreach (var en in Plugins.Enrichers)
        {
            try { await en.EnrichAsync(device, ectx, ct); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { Log($"{en.Name}: {ex.Message}"); }
        }
    }

    public static async Task<bool> IsTcpOpenAsync(IPAddress ip, int port, int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try { await s.ConnectAsync(ip, port, cts.Token); return true; }
        catch { ct.ThrowIfCancellationRequested(); return false; }
    }

    public void Dispose()
    {
        StopListening();
        foreach (var a in Adapters)
            if (a.PcapDevice is LibPcapLiveDevice d) { try { d.Close(); } catch { } }
    }
}
