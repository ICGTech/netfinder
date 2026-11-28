using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetFinder.Core.Net;

/// <summary>
/// Minimal SNMP v2c / v1 client (GET, GETNEXT and GETBULK walks), enough to read sysDescr, model and serial numbers,
/// printer supplies and switch tables with a read community such as "public". No external library.
/// </summary>
public static class Snmp
{
    /// <summary>UDP port of the agents (161; the self-test uses another one).</summary>
    public static int Port { get; set; } = 161;

    public const string SysDescr = "1.3.6.1.2.1.1.1.0";
    public const string SysObjectId = "1.3.6.1.2.1.1.2.0";
    public const string SysName = "1.3.6.1.2.1.1.5.0";
    public const string SysLocation = "1.3.6.1.2.1.1.6.0";
    /// <summary>ENTITY-MIB columns (walk with GETNEXT, index differs per vendor).</summary>
    public const string EntModelName = "1.3.6.1.2.1.47.1.1.1.1.13";
    public const string EntSerialNum = "1.3.6.1.2.1.47.1.1.1.1.11";
    public const string EntMfgName = "1.3.6.1.2.1.47.1.1.1.1.12";
    /// <summary>Printer-MIB prtGeneralPrinterName.1 and prtGeneralSerialNumber.1, HOST-RESOURCES hrDeviceDescr.1.</summary>
    public const string PrinterName = "1.3.6.1.2.1.43.5.1.1.16.1";
    public const string PrinterSerial = "1.3.6.1.2.1.43.5.1.1.17.1";
    public const string HrDeviceDescr1 = "1.3.6.1.2.1.25.3.2.1.3.1";

    /// <summary>GET. Returns oid → value for the OIDs that exist (missing ones are left out). Null when the device did not answer.</summary>
    public static async Task<Dictionary<string, string>?> GetAsync(IPAddress ip, string community, IReadOnlyList<string> oids, int timeoutMs, CancellationToken ct, int version = 1, int port = 0)
    {
        var (r, _) = await RequestAsync(ip, port, community, 0xA0, oids, timeoutMs, ct, version);
        return r?.Where(v => v.Text != null).GroupBy(v => v.Oid).ToDictionary(g => g.Key, g => g.First().Text!);
    }

    /// <summary>
    /// Every value under <paramref name="root"/> in OID order (GETBULK with v2c, GETNEXT with v1).
    /// Null when the device did not answer at all; stops at <paramref name="maxRows"/> rows.
    /// </summary>
    public static async Task<List<SnmpVar>?> WalkAsync(IPAddress ip, string community, string root, int timeoutMs, CancellationToken ct,
        int version = 1, int maxRows = 20_000, int port = 0)
    {
        var rows = new List<SnmpVar>();
        var oid = root;
        var reps = 24;
        while (rows.Count < maxRows)
        {
            var (r, err) = version == 0
                ? await RequestAsync(ip, port, community, 0xA1, new[] { oid }, timeoutMs, ct, 0)
                : await RequestAsync(ip, port, community, 0xA5, new[] { oid }, timeoutMs, ct, 1, 0, reps);
            if (r == null) return rows.Count > 0 ? rows : null;
            if (err == 1 && reps > 2) { reps /= 3; continue; } // tooBig: ask for fewer rows at a time
            if (r.Count == 0) return rows;                       // v1 noSuchName = end of the MIB
            foreach (var v in r)
            {
                if (v.Tag == 0x82 || !v.Oid.StartsWith(root + ".", StringComparison.Ordinal)) return rows; // left the subtree
                if (CompareOid(v.Oid, oid) <= 0) return rows;   // a broken agent going backwards: stop instead of looping
                rows.Add(v);
                oid = v.Oid;
                if (rows.Count >= maxRows) break;
            }
        }
        return rows;
    }

    /// <summary>Numeric OID order ("1.3.6.1.2.1.2" &lt; "1.3.6.1.2.1.10").</summary>
    public static int CompareOid(string a, string b)
    {
        var x = a.Split('.'); var y = b.Split('.');
        for (var i = 0; i < Math.Min(x.Length, y.Length); i++)
        {
            var c = ulong.Parse(x[i]).CompareTo(ulong.Parse(y[i]));
            if (c != 0) return c;
        }
        return x.Length.CompareTo(y.Length);
    }

    /// <summary>The arcs after <paramref name="column"/> ("…​.2.1.5.7" under "….2.1.5" → [7]).</summary>
    public static int[] Index(string oid, string column) =>
        oid.Length > column.Length + 1 ? oid[(column.Length + 1)..].Split('.').Select(p => (int)Math.Min(uint.Parse(p), int.MaxValue)).ToArray() : Array.Empty<int>();

    /// <summary>
    /// First non-empty value under <paramref name="column"/> (follows GETNEXT up to <paramref name="maxSteps"/> rows).
    /// </summary>
    public static async Task<(string Oid, string Value)?> FirstInColumnAsync(IPAddress ip, string community, string column, int timeoutMs, CancellationToken ct, int maxSteps = 8, int port = 0)
    {
        var oid = column;
        for (var i = 0; i < maxSteps; i++)
        {
            var (r, _) = await RequestAsync(ip, port, community, 0xA1, new[] { oid }, timeoutMs, ct, 1);
            if (r == null || r.Count == 0) return null;
            var v = r[0];
            if (!v.Oid.StartsWith(column + ".", StringComparison.Ordinal)) return null; // left the column
            if (!string.IsNullOrWhiteSpace(v.Text)) return (v.Oid, v.Text!.Trim());
            oid = v.Oid;
        }
        return null;
    }

    /// <summary>The answer's values (null when nothing came back) and its error status (0 = fine, 1 = tooBig, 2 = noSuchName…).</summary>
    private static async Task<(List<SnmpVar>? Vars, int Error)> RequestAsync(IPAddress ip, int port, string community, byte pdu, IReadOnlyList<string> oids,
        int timeoutMs, CancellationToken ct, int version, int nonRepeaters = 0, int maxRepetitions = 0)
    {
        var id = Random.Shared.Next(1, int.MaxValue);
        var packet = Encode(version, community, pdu, id, oids, nonRepeaters, maxRepetitions);
        if (port == 0) port = Port;
        using var udp = new UdpClient(ip.AddressFamily);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            await udp.SendAsync(packet, new IPEndPoint(ip, port), ct);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            try
            {
                while (true)
                {
                    var res = await udp.ReceiveAsync(cts.Token);
                    if (!res.RemoteEndPoint.Address.Equals(ip)) continue;
                    var parsed = Decode(res.Buffer, out var rid, out var err);
                    if (parsed == null || rid != id) continue;
                    if (err != 0) return (new List<SnmpVar>(), err); // e.g. v1 noSuchName
                    return (parsed, 0);
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            catch (SocketException) { return (null, -1); } // ICMP "port unreachable": no SNMP agent there
        }
        return (null, -1);
    }

    // ───────────────────────────── BER encoding ─────────────────────────────

    /// <param name="field2">error-status, or non-repeaters in a GETBULK</param>
    /// <param name="field3">error-index, or max-repetitions in a GETBULK</param>
    public static byte[] Encode(int version, string community, byte pdu, int requestId, IReadOnlyList<string> oids, int field2 = 0, int field3 = 0)
    {
        var binds = new List<byte>();
        foreach (var o in oids) binds.AddRange(Tlv(0x30, Concat(Tlv(0x06, EncodeOid(o)), new byte[] { 0x05, 0x00 })));
        var pduBody = Concat(Tlv(0x02, EncodeInt(requestId)), Tlv(0x02, EncodeInt(field2)), Tlv(0x02, EncodeInt(field3)), Tlv(0x30, binds.ToArray()));
        var msg = Concat(Tlv(0x02, EncodeInt(version)), Tlv(0x04, Encoding.ASCII.GetBytes(community)), Tlv(pdu, pduBody));
        return Tlv(0x30, msg);
    }

    private static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    /// <summary>A response the self-test's fake agent sends back.</summary>
    public static byte[] EncodeResponse(int version, string community, int requestId, int errorStatus, IReadOnlyList<(string Oid, byte Tag, byte[] Value)> binds)
    {
        var b = new List<byte>();
        foreach (var (o, tag, v) in binds) b.AddRange(Tlv(0x30, Concat(Tlv(0x06, EncodeOid(o)), Tlv(tag, v))));
        var pduBody = Concat(Tlv(0x02, EncodeInt(requestId)), Tlv(0x02, EncodeInt(errorStatus)), Tlv(0x02, EncodeInt(0)), Tlv(0x30, b.ToArray()));
        return Tlv(0x30, Concat(Tlv(0x02, EncodeInt(version)), Tlv(0x04, Encoding.ASCII.GetBytes(community)), Tlv(0xA2, pduBody)));
    }

    /// <summary>The self-test's fake agent reads requests with this: version, community, PDU type, request id, non-repeaters, max-repetitions, OIDs.</summary>
    public static (int Version, string Community, byte Pdu, int RequestId, int Field2, int Field3, List<string> Oids)? DecodeRequest(byte[] buf)
    {
        try
        {
            var pos = 0;
            if (!Read(buf, ref pos, out var tag, out var msg) || tag != 0x30) return null;
            var p = 0;
            Read(msg, ref p, out _, out var ver);
            Read(msg, ref p, out _, out var com);
            Read(msg, ref p, out var pduTag, out var pdu);
            var q = 0;
            Read(pdu, ref q, out _, out var rid);
            Read(pdu, ref q, out _, out var f2);
            Read(pdu, ref q, out _, out var f3);
            Read(pdu, ref q, out _, out var binds);
            var oids = new List<string>();
            var b = 0;
            while (b < binds.Length && Read(binds, ref b, out _, out var vb)) { var v = 0; Read(vb, ref v, out _, out var o); oids.Add(DecodeOid(o)); }
            return ((int)ToLong(ver), Encoding.ASCII.GetString(com), pduTag, (int)ToLong(rid), (int)ToLong(f2), (int)ToLong(f3), oids);
        }
        catch { return null; }
    }

    public static byte[] EncodeInt(int v) => EncodeIntBytes(v);

    private static byte[] Tlv(byte tag, byte[] value)
    {
        var len = value.Length;
        byte[] l = len < 0x80 ? new[] { (byte)len } : len < 0x100 ? new byte[] { 0x81, (byte)len } : new byte[] { 0x82, (byte)(len >> 8), (byte)len };
        return Concat(new[] { tag }, l, value);
    }

    private static byte[] EncodeIntBytes(int v)
    {
        var b = BitConverter.GetBytes(v);
        if (BitConverter.IsLittleEndian) Array.Reverse(b);
        var i = 0;
        while (i < 3 && ((b[i] == 0 && (b[i + 1] & 0x80) == 0) || (b[i] == 0xFF && (b[i + 1] & 0x80) != 0))) i++;
        return b[i..];
    }

    public static byte[] EncodeOid(string oid)
    {
        var arcs = oid.Split('.', StringSplitOptions.RemoveEmptyEntries).Select(uint.Parse).ToArray();
        var res = new List<byte> { (byte)(arcs[0] * 40 + arcs[1]) };
        foreach (var a in arcs.Skip(2))
        {
            var tmp = new Stack<byte>();
            var v = a;
            tmp.Push((byte)(v & 0x7F));
            while ((v >>= 7) > 0) tmp.Push((byte)(0x80 | (v & 0x7F)));
            res.AddRange(tmp);
        }
        return res.ToArray();
    }

    // ───────────────────────────── BER decoding ─────────────────────────────

    internal static List<SnmpVar>? Decode(byte[] buf, out int requestId, out int errorStatus)
    {
        requestId = -1; errorStatus = -1;
        try
        {
            var pos = 0;
            if (!Read(buf, ref pos, out var tag, out var msg) || tag != 0x30) return null;
            var p = 0;
            Read(msg, ref p, out _, out _);                 // version
            Read(msg, ref p, out _, out _);                 // community
            if (!Read(msg, ref p, out var pduTag, out var pdu) || pduTag != 0xA2) return null;
            var q = 0;
            Read(pdu, ref q, out _, out var rid); requestId = (int)ToLong(rid);
            Read(pdu, ref q, out _, out var es); errorStatus = (int)ToLong(es);
            Read(pdu, ref q, out _, out _);                 // error index
            Read(pdu, ref q, out _, out var binds);
            var list = new List<SnmpVar>();
            var b = 0;
            while (b < binds.Length && Read(binds, ref b, out _, out var vb))
            {
                var v = 0;
                Read(vb, ref v, out _, out var oidBytes);
                Read(vb, ref v, out var vt, out var val);
                list.Add(new SnmpVar(DecodeOid(oidBytes), vt, val, Value(vt, val)));
            }
            return list;
        }
        catch { return null; }
    }

    private static bool Read(byte[] b, ref int pos, out byte tag, out byte[] value)
    {
        tag = 0; value = Array.Empty<byte>();
        if (pos + 2 > b.Length) return false;
        tag = b[pos++];
        int len = b[pos++];
        if ((len & 0x80) != 0)
        {
            var n = len & 0x7F;
            if (n is 0 or > 3 || pos + n > b.Length) return false;
            len = 0;
            for (var i = 0; i < n; i++) len = (len << 8) | b[pos++];
        }
        if (pos + len > b.Length) return false;
        value = b[pos..(pos + len)];
        pos += len;
        return true;
    }

    internal static long ToLong(byte[] b)
    {
        long v = b.Length > 0 && (b[0] & 0x80) != 0 ? -1 : 0;
        foreach (var x in b) v = (v << 8) | x;
        return v;
    }

    internal static string DecodeOid(byte[] b)
    {
        if (b.Length == 0) return "";
        var parts = new List<ulong> { (ulong)(b[0] / 40), (ulong)(b[0] % 40) };
        ulong cur = 0;
        for (var i = 1; i < b.Length; i++)
        {
            cur = (cur << 7) | (ulong)(uint)(b[i] & 0x7F);
            if ((b[i] & 0x80) == 0) { parts.Add(cur); cur = 0; }
        }
        return string.Join(".", parts);
    }

    private static string? Value(byte tag, byte[] v) => tag switch
    {
        0x04 => OctetString(v),
        0x06 => DecodeOid(v),
        0x02 => ToLong(v).ToString(),
        0x40 when v.Length == 4 => new IPAddress(v).ToString(),
        0x41 or 0x42 or 0x43 or 0x46 => ((ulong)ToLong(v.Length > 0 && (v[0] & 0x80) != 0 ? new byte[] { 0 }.Concat(v).ToArray() : v)).ToString(),
        _ => null, // NULL, noSuchObject (0x80), noSuchInstance (0x81), endOfMibView (0x82)
    };

    private static string OctetString(byte[] v)
    {
        var s = Encoding.UTF8.GetString(v).TrimEnd('\0');
        var printable = s.Count(c => !char.IsControl(c) || c is '\r' or '\n' or '\t');
        return s.Length > 0 && printable >= s.Length * 0.9 ? s.Trim() : Convert.ToHexString(v);
    }
}

/// <summary>One value from an answer: its OID, BER tag, raw bytes and the value as text (null for "no such object").</summary>
public sealed record SnmpVar(string Oid, byte Tag, byte[] Raw, string? Text)
{
    /// <summary>The number in an INTEGER / Counter / Gauge, or null.</summary>
    public long? Number => Tag is 0x02 or 0x41 or 0x42 or 0x43 or 0x46 && Text != null && long.TryParse(Text, out var n) ? n : null;

    /// <summary>"AA:BB:CC:DD:EE:FF" when the raw value is 6 bytes (a MAC address), else null.</summary>
    public string? Mac => Tag == 0x04 && Raw.Length == 6 ? string.Join(":", Raw.Select(b => b.ToString("X2"))) : null;
}
