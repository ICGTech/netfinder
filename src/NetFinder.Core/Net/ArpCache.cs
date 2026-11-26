using System.Diagnostics;
using System.Net;
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

    // Windows:  "  10.10.20.1            e4-8d-8c-aa-00-01     dynamic"
    [GeneratedRegex(@"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})")]
    private static partial Regex ArpLine();
}
