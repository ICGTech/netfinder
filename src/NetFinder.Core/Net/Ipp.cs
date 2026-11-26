using System.Net;
using System.Text;

namespace NetFinder.Core.Net;

/// <summary>
/// IPP Get-Printer-Attributes (port 631): asks a printer for its make-and-model without printing anything.
/// </summary>
public static class Ipp
{
    private static readonly HttpClient Http = new(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(4) };
    private static readonly string[] Paths = { "/ipp/print", "/ipp", "/", "/ipp/printer" };
    private static readonly string[] Wanted =
        { "printer-make-and-model", "printer-device-id", "printer-name", "printer-info", "printer-location", "printer-firmware-string-version" };

    /// <summary>Attribute name → value (first value). Null when no IPP printer answered.</summary>
    public static async Task<Dictionary<string, string>?> GetPrinterAttributesAsync(IPAddress ip, CancellationToken ct, int port = 631, IEnumerable<string>? paths = null)
    {
        foreach (var path in paths ?? Paths)
        {
            var uri = $"ipp://{ip}:{port}{path}";
            try
            {
                using var content = new ByteArrayContent(BuildRequest(uri));
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/ipp");
                using var resp = await Http.PostAsync($"http://{ip}:{port}{path}", content, ct);
                if (!resp.IsSuccessStatusCode) continue;
                var body = await resp.Content.ReadAsByteArrayAsync(ct);
                var attrs = ParseResponse(body, out var status);
                if (attrs == null) continue;
                if (status >= 0x0400 || attrs.Count == 0) continue; // e.g. client-error-not-found: try the next path
                return attrs;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { }
        }
        return null;
    }

    internal static byte[] BuildRequest(string printerUri)
    {
        var ms = new MemoryStream();
        void B(params byte[] b) => ms.Write(b);
        void Attr(byte tag, string name, string value)
        {
            var n = Encoding.UTF8.GetBytes(name);
            var v = Encoding.UTF8.GetBytes(value);
            B(tag, (byte)(n.Length >> 8), (byte)n.Length); B(n);
            B((byte)(v.Length >> 8), (byte)v.Length); B(v);
        }
        B(0x02, 0x00);       // IPP 2.0 (1.1 printers accept it too)
        B(0x00, 0x0B);       // Get-Printer-Attributes
        B(0x00, 0x00, 0x00, 0x01); // request-id
        B(0x01);             // operation-attributes-tag
        Attr(0x47, "attributes-charset", "utf-8");
        Attr(0x48, "attributes-natural-language", "en");
        Attr(0x45, "printer-uri", printerUri);
        for (var i = 0; i < Wanted.Length; i++) Attr(0x44, i == 0 ? "requested-attributes" : "", Wanted[i]);
        B(0x03);             // end-of-attributes
        return ms.ToArray();
    }

    internal static Dictionary<string, string>? ParseResponse(byte[] b, out int status)
    {
        status = -1;
        if (b.Length < 9) return null;
        status = (b[2] << 8) | b[3];
        var res = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var pos = 8;
        string? last = null;
        var group = 0;
        while (pos < b.Length)
        {
            var tag = b[pos++];
            if (tag == 0x03) break;      // end-of-attributes
            if (tag < 0x10) { group = tag; continue; } // delimiter: 0x01 operation, 0x04 printer attributes
            if (pos + 2 > b.Length) break;
            int nl = (b[pos] << 8) | b[pos + 1]; pos += 2;
            if (pos + nl + 2 > b.Length) break;
            var name = nl > 0 ? Encoding.UTF8.GetString(b, pos, nl) : last;
            pos += nl;
            int vl = (b[pos] << 8) | b[pos + 1]; pos += 2;
            if (pos + vl > b.Length) break;
            // text, name, keyword, uri, charset, language, mime types
            if (group == 0x04 && name != null && tag is >= 0x41 and <= 0x49 && !res.ContainsKey(name))
                res[name] = Encoding.UTF8.GetString(b, pos, vl).Trim();
            pos += vl;
            last = name;
        }
        return res;
    }

    /// <summary>"MFG:HP;MDL:LaserJet Pro M404dn;CMD:..." → ("HP", "LaserJet Pro M404dn").</summary>
    public static (string? Make, string? Model) ParseDeviceId(string? id)
    {
        if (string.IsNullOrEmpty(id)) return (null, null);
        string? mfg = null, mdl = null;
        foreach (var part in id.Split(';'))
        {
            var i = part.IndexOf(':');
            if (i <= 0) continue;
            var k = part[..i].Trim().ToUpperInvariant();
            var v = part[(i + 1)..].Trim();
            if (k is "MFG" or "MANUFACTURER") mfg ??= v;
            if (k is "MDL" or "MODEL") mdl ??= v;
        }
        return (mfg, mdl);
    }
}
