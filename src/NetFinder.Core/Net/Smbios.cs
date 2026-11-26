using System.Text;

namespace NetFinder.Core.Net;

/// <summary>What the PC's firmware (SMBIOS) says: maker, model, serial number, board, installed RAM.</summary>
public sealed record SmbiosInfo(string? Manufacturer, string? Product, string? Version, string? Serial, string? Family, string? Sku,
    string? BoardMaker, string? BoardProduct, string? ChassisSerial, string? BiosVersion, long RamBytes);

/// <summary>
/// Parses raw SMBIOS tables. Windows keeps a copy in the registry
/// (HKLM\SYSTEM\CurrentControlSet\Services\mssmbios\Data, value SMBiosData), so a PC's serial number and RAM
/// can be read over the Remote Registry when WMI is blocked.
/// </summary>
public static class Smbios
{
    /// <param name="data">Windows' RawSMBIOSData (8-byte header + tables) or, with <paramref name="windowsHeader"/> false, the bare tables.</param>
    public static SmbiosInfo? Parse(byte[] data, bool windowsHeader = true)
    {
        int off = 0, end = data.Length;
        if (windowsHeader)
        {
            if (data.Length < 8) return null;
            var len = BitConverter.ToInt32(data, 4);
            off = 8;
            end = len > 0 ? Math.Min(data.Length, 8 + len) : data.Length;
        }
        string? maker = null, product = null, version = null, serial = null, family = null, sku = null;
        string? boardMaker = null, boardProduct = null, chassisSerial = null, bios = null;
        long ram = 0;
        var any = false;
        while (off + 4 <= end)
        {
            var type = data[off];
            int len = data[off + 1];
            if (len < 4 || off + len > end) break;
            // the strings follow the formatted part: "one\0two\0\0", or "\0\0" when there are none
            var strings = new List<string>();
            var p = off + len;
            while (p < end)
            {
                if (data[p] == 0)
                {
                    p++;
                    if (strings.Count == 0 && p < end && data[p] == 0) p++;
                    break;
                }
                var s = p;
                while (p < end && data[p] != 0) p++;
                strings.Add(Encoding.Latin1.GetString(data, s, p - s));
                p++;
            }
            var o = off;
            string? Str(int at)
            {
                if (at >= len) return null;
                int idx = data[o + at];
                return idx > 0 && idx <= strings.Count && strings[idx - 1].Trim() is { Length: > 0 } v ? v : null;
            }
            switch (type)
            {
                case 0: bios ??= Str(5); any = true; break;
                case 1:
                    maker ??= Str(4); product ??= Str(5); version ??= Str(6); serial ??= Str(7);
                    if (len > 0x19) sku ??= Str(0x19);
                    if (len > 0x1A) family ??= Str(0x1A);
                    any = true;
                    break;
                case 2: boardMaker ??= Str(4); boardProduct ??= Str(5); any = true; break;
                case 3: chassisSerial ??= Str(7); any = true; break;
                case 17 when len > 0x0D:
                {
                    var size = BitConverter.ToUInt16(data, off + 0x0C);
                    if (size is 0 or 0xFFFF) break;
                    long mb = size == 0x7FFF && len >= 0x20 ? BitConverter.ToUInt32(data, off + 0x1C) & 0x7FFFFFFF
                        : (size & 0x8000) != 0 ? (size & 0x7FFF) / 1024 : size;
                    ram += mb * 1024 * 1024;
                    break;
                }
                case 127: off = end; continue;
            }
            off = p;
        }
        return any ? new SmbiosInfo(maker, product, version, serial, family, sku, boardMaker, boardProduct, chassisSerial, bios, ram) : null;
    }
}
