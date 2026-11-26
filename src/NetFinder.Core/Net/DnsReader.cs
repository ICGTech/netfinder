using System.Text;

namespace NetFinder.Core.Net;

/// <summary>Minimal DNS / mDNS message reader (enough for discovery).</summary>
public sealed class DnsMessage
{
    public ushort Id;
    public ushort Flags;
    public bool IsResponse => (Flags & 0x8000) != 0;
    public int Opcode => (Flags >> 11) & 0xf;
    public List<(string Name, ushort Type)> Questions { get; } = new();
    public List<DnsRecord> Records { get; } = new(); // answers + authority + additional

    public static DnsMessage? Parse(ReadOnlySpan<byte> m)
    {
        if (m.Length < 12) return null;
        var msg = new DnsMessage { Id = (ushort)(m[0] << 8 | m[1]), Flags = (ushort)(m[2] << 8 | m[3]) };
        int qd = m[4] << 8 | m[5], an = m[6] << 8 | m[7], ns = m[8] << 8 | m[9], ar = m[10] << 8 | m[11];
        var off = 12;
        try
        {
            for (var i = 0; i < qd && i < 64; i++)
            {
                var name = ReadName(m, ref off);
                if (off + 4 > m.Length) return msg;
                msg.Questions.Add((name, (ushort)(m[off] << 8 | m[off + 1])));
                off += 4;
            }
            var total = Math.Min(an + ns + ar, 256);
            for (var i = 0; i < total; i++)
            {
                var name = ReadName(m, ref off);
                if (off + 10 > m.Length) return msg;
                var type = (ushort)(m[off] << 8 | m[off + 1]);
                var rdlen = m[off + 8] << 8 | m[off + 9];
                off += 10;
                if (off + rdlen > m.Length) return msg;
                var rec = new DnsRecord(name, type, off, rdlen);
                switch (type)
                {
                    case 1 when rdlen == 4: rec.Address = new System.Net.IPAddress(m.Slice(off, 4)); break;
                    case 12: case 5: { var o = off; rec.Target = ReadName(m, ref o); break; }
                    case 33 when rdlen > 6: { var o = off + 6; rec.Port = m[off + 4] << 8 | m[off + 5]; rec.Target = ReadName(m, ref o); break; }
                    case 16: rec.Txt = ReadTxt(m.Slice(off, rdlen)); break;
                }
                msg.Records.Add(rec);
                off += rdlen;
            }
        }
        catch (IndexOutOfRangeException) { }
        catch (ArgumentOutOfRangeException) { }
        return msg;
    }

    public static string ReadName(ReadOnlySpan<byte> m, ref int off)
    {
        var sb = new StringBuilder();
        var jumped = false;
        var pos = off;
        for (var guard = 0; guard < 128; guard++)
        {
            var len = m[pos];
            if (len == 0) { pos++; break; }
            if ((len & 0xc0) == 0xc0)
            {
                var ptr = (len & 0x3f) << 8 | m[pos + 1];
                if (!jumped) off = pos + 2;
                jumped = true;
                pos = ptr;
                continue;
            }
            pos++;
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.UTF8.GetString(m.Slice(pos, len)));
            pos += len;
        }
        if (!jumped) off = pos;
        return sb.ToString();
    }

    private static List<string> ReadTxt(ReadOnlySpan<byte> d)
    {
        var l = new List<string>();
        var i = 0;
        while (i < d.Length)
        {
            var len = d[i++];
            if (i + len > d.Length) break;
            if (len > 0) l.Add(Encoding.UTF8.GetString(d.Slice(i, len)));
            i += len;
        }
        return l;
    }
}

public sealed class DnsRecord
{
    public DnsRecord(string name, ushort type, int dataOffset, int dataLength) { Name = name; Type = type; DataOffset = dataOffset; DataLength = dataLength; }
    public string Name { get; }
    public ushort Type { get; }
    public int DataOffset { get; }
    public int DataLength { get; }
    public System.Net.IPAddress? Address { get; set; }
    public string? Target { get; set; }
    public int Port { get; set; }
    public List<string>? Txt { get; set; }
}
