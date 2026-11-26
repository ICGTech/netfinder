using System.Net;
using System.Runtime.InteropServices;

namespace NetFinder.Core.Net;

/// <summary>Windows IP Helper API (works without Npcap).</summary>
public static class WindowsNet
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref uint physAddrLen);

    /// <summary>
    /// Asks Windows to ARP for <paramref name="ip"/> (same subnet only). Returns the MAC, or null if nobody answered.
    /// Blocks up to ~3 s when the address is free.
    /// </summary>
    public static string? ResolveMac(IPAddress ip, IPAddress? source = null)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var mac = new byte[6];
        uint len = 6;
        var dst = BitConverter.ToUInt32(ip.GetAddressBytes(), 0);
        var src = source == null ? 0 : BitConverter.ToUInt32(source.GetAddressBytes(), 0);
        try
        {
            if (SendARP(dst, src, mac, ref len) != 0 || len != 6) return null;
        }
        catch { return null; }
        return Mac.Format(mac);
    }

    /// <summary>Is the real Npcap driver installed (not old WinPcap)?</summary>
    public static bool NpcapInstalled =>
        OperatingSystem.IsWindows() && File.Exists(Path.Combine(Environment.SystemDirectory, "Npcap", "wpcap.dll"));
}
