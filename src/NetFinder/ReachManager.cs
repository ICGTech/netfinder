using System.Diagnostics;
using System.Net;
using NetFinder.Core;
using NetFinder.Core.Model;
using NetFinder.Core.Net;

namespace NetFinder;

/// <summary>
/// Makes a device on another subnet reachable by adding a TEMPORARY extra IP in its subnet
/// to the network card (netsh ... store=active: gone after reboot, and removed when the app closes).
/// Example: PC is 10.10.20.5, camera is 192.168.1.64 → we add 192.168.1.250/24 to the same card,
/// then the browser can open http://192.168.1.64 directly.
/// </summary>
public sealed class ReachManager
{
    private readonly NetworkEngine _engine;
    private readonly List<(Adapter Adapter, IPAddress Ip)> _added = new();

    public ReachManager(NetworkEngine engine) { _engine = engine; }

    public IReadOnlyList<(Adapter Adapter, IPAddress Ip)> Added => _added;

    public async Task<(bool Ok, string Message)> MakeReachableAsync(Device device)
    {
        IPAddress? ip; string? adapterId;
        lock (device) { ip = device.Ip; adapterId = device.AdapterId; }
        if (ip == null) return (false, "This device has no known IP address yet.");
        var adapter = _engine.AdapterById(adapterId) ?? _engine.Adapters.FirstOrDefault(a => a.IsUp);
        if (adapter == null) return (false, "No network adapter found.");
        if (adapter.OwnsSubnetOf(ip)) return (true, "Already reachable.");

        var prefix = _engine.Settings.ReachPrefix;
        var subnet = Subnet.Of(ip, prefix);
        var alias = await PickFreeAddressAsync(adapter, subnet, Ip4.ToUInt(ip));
        if (alias == null) return (false, $"Could not find a free address in {subnet}.");

        var mask = Ip4.FromUInt(subnet.Mask);
        var name = adapter.FriendlyName;
        // Allow a static IP next to DHCP (Windows 10 2004+). Harmless if already static.
        await RunAsync("netsh", $"interface ipv4 set interface \"{name}\" dhcpstaticipcoexistence=enabled");
        var (code, output) = await RunAsync("netsh", $"interface ipv4 add address name=\"{name}\" address={alias} mask={mask} store=active");
        if (code != 0)
        {
            var (code2, output2) = await RunAsync("powershell", $"-NoProfile -Command \"New-NetIPAddress -InterfaceIndex {adapter.InterfaceIndex} -IPAddress {alias} -PrefixLength {prefix} -PolicyStore ActiveStore -ErrorAction Stop | Out-Null\"");
            if (code2 != 0) return (false, $"Windows refused to add {alias}/{prefix} to \"{name}\".\n\n{output.Trim()}\n{output2.Trim()}");
        }
        _added.Add((adapter, alias));
        _engine.Log($"Added temporary IP {alias}/{prefix} to {name} to reach {ip}");
        // Windows needs a moment before the address is usable (duplicate address detection)
        for (var i = 0; i < 20; i++)
        {
            await Task.Delay(250);
            adapter.RefreshFromOs();
            if (adapter.OwnsSubnetOf(ip)) break;
        }
        await Task.Delay(1000);
        _engine.RefreshAdapterAddresses();
        return (true, $"Added temporary IP {alias}/{prefix} on \"{name}\". It will be removed when you close the program.");
    }

    private async Task<IPAddress?> PickFreeAddressAsync(Adapter adapter, Subnet subnet, uint deviceIp)
    {
        var candidates = new List<uint>();
        for (var v = subnet.Broadcast - 1; v > subnet.Network && candidates.Count < 40; v--)
            if (v != deviceIp && _engine.Store.FindByIp(Ip4.FromUInt(v)) == null) candidates.Add(v);
        // ask the wire whether anyone uses the first candidates (ARP probe), pick the first silent one
        foreach (var c in candidates.Take(6))
        {
            if (_engine.CaptureAvailable)
            {
                try { _engine.SendFrame(adapter, PacketBuilder.ArpRequest(adapter.MacBytes, 0, c)); } catch { }
                await Task.Delay(400);
            }
            if (_engine.Store.FindByIp(Ip4.FromUInt(c)) == null) return Ip4.FromUInt(c);
        }
        return candidates.Count > 0 ? Ip4.FromUInt(candidates[0]) : null;
    }

    public async Task RemoveAllAsync()
    {
        foreach (var (a, ip) in _added.ToList())
        {
            await RunAsync("netsh", $"interface ipv4 delete address name=\"{a.FriendlyName}\" address={ip} store=active");
            _engine.Log($"Removed temporary IP {ip} from {a.FriendlyName}");
        }
        _added.Clear();
        _engine.RefreshAdapterAddresses();
    }

    public void RemoveAllBlocking()
    {
        foreach (var (a, ip) in _added.ToList())
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo("netsh", $"interface ipv4 delete address name=\"{a.FriendlyName}\" address={ip} store=active")
                    { CreateNoWindow = true, UseShellExecute = false });
                p?.WaitForExit(5000);
            }
            catch { }
        }
        _added.Clear();
    }

    private static async Task<(int Code, string Output)> RunAsync(string exe, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                CreateNoWindow = true, UseShellExecute = false,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            var o = await p.StandardOutput.ReadToEndAsync();
            var e = await p.StandardError.ReadToEndAsync();
            await p.WaitForExitAsync();
            return (p.ExitCode, (o + e).Trim());
        }
        catch (Exception ex) { return (-1, ex.Message); }
    }
}
