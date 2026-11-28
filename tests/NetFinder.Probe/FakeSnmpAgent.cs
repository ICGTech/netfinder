using System.Net;
using System.Net.Sockets;
using System.Text;
using NetFinder.Core.Net;

/// <summary>A tiny SNMP v1/v2c agent for the self-test: answers GET, GETNEXT and GETBULK from a fixed table.</summary>
internal sealed class FakeSnmpAgent : IDisposable
{
    private readonly UdpClient _udp;
    private readonly List<(string Oid, byte Tag, byte[] Value)> _rows;
    private readonly string _community;
    private readonly CancellationTokenSource _cts = new();
    public int Requests;
    public int BulkRequests;

    public FakeSnmpAgent(IPAddress ip, int port, string community, IEnumerable<(string Oid, byte Tag, byte[] Value)> rows)
    {
        _community = community;
        _rows = rows.OrderBy(r => r.Oid, Comparer<string>.Create(Snmp.CompareOid)).ToList();
        _udp = new UdpClient(new IPEndPoint(ip, port));
        _ = Task.Run(LoopAsync);
    }

    public static (byte, byte[]) Int(long v) => (0x02, Snmp.EncodeInt((int)v));
    public static (byte, byte[]) Str(string s) => (0x04, Encoding.UTF8.GetBytes(s));
    public static (byte, byte[]) Bytes(params byte[] b) => (0x04, b);
    public static (byte, byte[]) Counter(uint v)
    {
        var b = BitConverter.GetBytes(v); if (BitConverter.IsLittleEndian) Array.Reverse(b);
        var i = 0; while (i < 3 && b[i] == 0) i++;
        var r = b[i..];
        return (0x41, (r[0] & 0x80) != 0 ? new byte[] { 0 }.Concat(r).ToArray() : r);
    }
    public static (byte, byte[]) Gauge(uint v) => (0x42, Counter(v).Item2);
    public static (byte, byte[]) Oid(string o) => (0x06, Snmp.EncodeOid(o));

    private async Task LoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            UdpReceiveResult res;
            try { res = await _udp.ReceiveAsync(_cts.Token); } catch { return; }
            var q = Snmp.DecodeRequest(res.Buffer);
            if (q is not { } r) continue;
            if (r.Community != _community && !r.Community.StartsWith(_community + "@")) continue; // wrong community: silence, like a real agent
            Interlocked.Increment(ref Requests);
            var binds = new List<(string, byte, byte[])>();
            var err = 0;
            (string, byte, byte[])? Next(string oid) => _rows.Where(x => Snmp.CompareOid(x.Oid, oid) > 0).Select(x => ((string, byte, byte[])?)(x.Oid, x.Tag, x.Value)).FirstOrDefault();
            switch (r.Pdu)
            {
                case 0xA0:
                    foreach (var o in r.Oids)
                    {
                        var hit = _rows.FirstOrDefault(x => x.Oid == o);
                        if (hit.Oid != null) binds.Add((hit.Oid, hit.Tag, hit.Value));
                        else if (r.Version == 0) { err = 2; break; }
                        else binds.Add((o, 0x80, Array.Empty<byte>()));
                    }
                    break;
                case 0xA1:
                    foreach (var o in r.Oids)
                    {
                        if (Next(o) is { } n) binds.Add(n);
                        else if (r.Version == 0) { err = 2; break; }
                        else binds.Add((o, 0x82, Array.Empty<byte>()));
                    }
                    break;
                case 0xA5:
                    Interlocked.Increment(ref BulkRequests);
                    foreach (var o in r.Oids)
                    {
                        var cur = o;
                        for (var i = 0; i < Math.Max(1, r.Field3); i++)
                        {
                            if (Next(cur) is not { } n) { binds.Add((cur, 0x82, Array.Empty<byte>())); break; }
                            binds.Add(n);
                            cur = n.Item1;
                        }
                    }
                    break;
                default: continue;
            }
            var answer = Snmp.EncodeResponse(r.Version, r.Community, r.RequestId, err, err != 0 ? new List<(string, byte, byte[])>() : binds);
            try { await _udp.SendAsync(answer, res.RemoteEndPoint); } catch { }
        }
    }

    public void Dispose() { _cts.Cancel(); _udp.Dispose(); }
}
