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
    public static bool IsLocallyAdministered(string mac) => (Convert.ToByte(mac[..2], 16) & 2) == 2;
}
