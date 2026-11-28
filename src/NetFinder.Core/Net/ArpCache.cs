using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace NetFinder.Core.Net;

/// <summary>Reads the operating system's ARP table (IP → MAC of devices the PC talked to recently).</summary>
public static partial class ArpCache
{
    public static List<(IPAddress Ip, string Mac)> Read()
    {
        var list = new List<(IPAddress, string)>();
        try
        {
            if (OperatingSystem.IsLinux() && File.Exists("/proc/net/arp"))
            {
                foreach (var line in File.ReadAllLines("/proc/net/arp").Skip(1))
                {
                    var p = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (p.Length >= 4 && p[2] != "0x0" && IPAddress.TryParse(p[0], out var ip)) list.Add((ip, p[3].ToUpperInvariant()));
                }
                return list;
            }
            var psi = new ProcessStartInfo("arp", "-a") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            foreach (Match m in ArpLine().Matches(output))
                if (IPAddress.TryParse(m.Groups[1].Value, out var ip))
                    list.Add((ip, m.Groups[2].Value.Replace('-', ':').ToUpperInvariant()));
        }
        catch { }
        return list;
    }

    /// <summary>One entry of the ARP table. <see cref="Fresh"/>: Windows heard from the device in the last ~30 s
    /// (state "Reachable"); false for an old entry kept from earlier ("Stale"); null when the state is not known.</summary>
    public readonly record struct Entry(IPAddress Ip, string Mac, bool? Fresh, string State);

    /// <summary>
    /// The ARP table with the state of each entry. Windows keeps entries of devices that left hours ago ("Stale"),
    /// so an entry alone does not mean the device is on now: only "Reachable" ones (fresh) do.
    /// </summary>
    public static List<Entry> ReadWithState()
    {
        var table = OperatingSystem.IsWindows() ? ReadWindowsTable() : null;
        return table ?? Read().Select(x => new Entry(x.Ip, x.Mac, null, "")).ToList();
    }

    private static readonly string[] States = { "Unreachable", "Incomplete", "Probe", "Delay", "Stale", "Reachable", "Permanent" };

    [DllImport("iphlpapi.dll", ExactSpelling = true)] private static extern int GetIpNetTable2(ushort family, out IntPtr table);
    [DllImport("iphlpapi.dll", ExactSpelling = true)] private static extern void FreeMibTable(IntPtr memory);

    /// <summary>GetIpNetTable2 (IPv4): MIB_IPNET_TABLE2 = count, then 88-byte MIB_IPNET_ROW2 rows from offset 8.</summary>
    private static List<Entry>? ReadWindowsTable()
    {
        var t = IntPtr.Zero;
        try
        {
            if (GetIpNetTable2(2, out t) != 0 || t == IntPtr.Zero) return null;
            var n = Marshal.ReadInt32(t);
            var list = new List<Entry>(n);
            for (var i = 0; i < n; i++)
            {
                var row = t + 8 + i * 88;
                if (Marshal.ReadInt16(row) != 2) continue;                 // SOCKADDR_INET.si_family = AF_INET
                var ip = new byte[4]; Marshal.Copy(row + 4, ip, 0, 4);      // sockaddr_in.sin_addr
                if (Marshal.ReadInt32(row + 72) != 6) continue;             // PhysicalAddressLength
                var mac = new byte[6]; Marshal.Copy(row + 40, mac, 0, 6);   // PhysicalAddress
                var state = Marshal.ReadInt32(row + 76);                    // NL_NEIGHBOR_STATE
                list.Add(new Entry(new IPAddress(ip), Mac.Format(mac), state == 5, state >= 0 && state < States.Length ? States[state] : state.ToString()));
            }
            return list;
        }
        catch { return null; }
        finally { if (t != IntPtr.Zero) try { FreeMibTable(t); } catch { } }
    }

    // Windows:  "  10.10.20.1            e4-8d-8c-aa-00-01     dynamic"
    [GeneratedRegex(@"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})")]
    private static partial Regex ArpLine();
}
