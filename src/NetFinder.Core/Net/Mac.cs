namespace NetFinder.Core.Net;

public static class Mac
{
    public static string Format(ReadOnlySpan<byte> b) =>
        $"{b[0]:X2}:{b[1]:X2}:{b[2]:X2}:{b[3]:X2}:{b[4]:X2}:{b[5]:X2}";

    public static byte[] Parse(string mac)
    {
        var hex = mac.Replace(":", "").Replace("-", "").Replace(".", "");
        return Convert.FromHexString(hex);
    }

    public static readonly byte[] Broadcast = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    public static bool IsGroup(ReadOnlySpan<byte> b) => (b[0] & 1) == 1;

    /// <summary>Locally administered (randomized / virtual) MAC.</summary>
    /// <summary>"AA:BB:…" of one device: not multicast / broadcast, not all zeros.</summary>
    public static bool IsUnicast(string mac) =>
        mac.Length == 17 && (Convert.ToByte(mac[..2], 16) & 1) == 0 && mac != "00:00:00:00:00:00";

    public static bool IsLocallyAdministered(string mac) => (Convert.ToByte(mac[..2], 16) & 2) == 2;
}
