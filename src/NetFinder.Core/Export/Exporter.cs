using System.IO.Compression;
using System.Net;
using System.Text;
using NetFinder.Core.Model;
using NetFinder.Core.Net;

namespace NetFinder.Core.Export;

/// <summary>Plain-text description of where a device is, shared by the list and the exports.</summary>
public static class DeviceText
{
    public static string Network(Device d)
    {
        if (d.Ip == null) return "—";
        if (d.IsSelf) return "This PC";
        if (d.Routed) return "Behind a router";
        if (d.Reachable) return "My subnet";
        if (d.BehindNvr != null) return $"Behind NVR {d.BehindNvr}";
        return $"Other: {Subnet.Of(d.Ip, 24)}";
    }
}

/// <summary>
/// Saves the device list as an Excel workbook (.xlsx, no Office needed), CSV, or an HTML report that prints well to PDF.
/// </summary>
public static class Exporter
{
    public static readonly string[] Columns =
    {
        "Type", "IP address", "Name", "Model", "Vendor", "Manufacturer", "MAC", "Network", "Subnet", "Open ports", "Serial number",
        "NVR / channel", "Camera status (NVR)", "Windows", "CPU", "RAM", "Disk", "Drives", "Graphics", "Logged-in user",
        "Found via", "All IPs", "First seen", "Last seen", "Risky ports", "Watch status",
    };

    /// <summary>Columns left out of a file when no device has a value in them.</summary>
    private static readonly HashSet<string> Optional = new() { "Risky ports", "Watch status" };

    /// <summary>One row of text per device, in IP order. Takes each device's lock while reading it.</summary>
    /// <param name="watch">"Up" / "Down since 10:42" for watched devices, "" for the others.</param>
    public static List<string[]> Rows(IEnumerable<Device> devices, Func<Device, string>? watch = null)
    {
        var rows = new List<string[]>();
        foreach (var d in devices.OrderBy(x => x.Ip == null ? long.MaxValue : (long)Ip4.ToUInt(x.Ip)))
            lock (d)
                rows.Add(new[]
                {
                    d.IsSelf ? "This PC" : d.EffectiveType,
                    d.Ip?.ToString() ?? "",
                    d.DisplayName,
                    d.Model ?? "",
                    d.Vendor ?? "",
                    d.Info.GetValueOrDefault("Manufacturer") ?? d.Info.GetValueOrDefault("Maker (SNMP)") ?? "",
                    d.Mac,
                    DeviceText.Network(d),
                    d.Ip == null ? "" : Subnet.Of(d.Ip, 24).ToString(),
                    string.Join(" ", d.OpenPorts),
                    d.Info.GetValueOrDefault("Serial number") ?? "",
                    d.Info.GetValueOrDefault("NVR channel")?.Replace("  ", " ") ?? (d.Info.TryGetValue("NVR cameras", out var n) ? $"NVR with {n} cameras" : ""),
                    d.Info.GetValueOrDefault("Status on NVR") ?? "",
                    d.Info.GetValueOrDefault("Windows") ?? "",
                    d.Info.GetValueOrDefault("CPU") ?? "",
                    d.Info.GetValueOrDefault("RAM") ?? "",
                    d.Info.GetValueOrDefault("Disk") ?? "",
                    d.Info.GetValueOrDefault("Drives") ?? (d.Info.TryGetValue("Drive C:", out var dc) ? "C: " + dc : ""),
                    d.Info.GetValueOrDefault("Graphics") ?? "",
                    d.Info.GetValueOrDefault("Logged-in user") ?? "",
                    string.Join(" ", d.Sources),
                    string.Join(" ", d.Ips),
                    d.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss"),
                    d.LastSeen.ToString("yyyy-MM-dd HH:mm:ss"),
                    Net.PortRisk.RiskyText(d.OpenPorts),
                    watch?.Invoke(d) ?? "",
                });
        return rows;
    }

    public static void Save(string path, IEnumerable<Device> devices, string title, Func<Device, string>? watch = null)
    {
        var all = Rows(devices, watch);
        // the optional columns are last, so the other columns keep their place (Html and Xlsx read "Network" at 7)
        var keep = Enumerable.Range(0, Columns.Length).Where(i => !Optional.Contains(Columns[i]) || all.Any(r => r[i].Length > 0)).ToArray();
        var columns = keep.Select(i => Columns[i]).ToArray();
        var rows = all.Select(r => keep.Select(i => r[i]).ToArray()).ToList();
        switch (Path.GetExtension(path).ToLowerInvariant())
        {
            case ".xlsx": SaveXlsx(path, columns, rows, title); break;
            case ".pdf": PdfReport.Save(path, columns, rows, title); break;
            case ".html": case ".htm": File.WriteAllText(path, Html(columns, rows, title), new UTF8Encoding(false)); break;
            default: File.WriteAllText(path, Csv(columns, rows), new UTF8Encoding(true)); break; // BOM: Excel opens Arabic/UTF-8 correctly
        }
    }

    // ───────────────────────────── CSV ─────────────────────────────

    public static string Csv(IReadOnlyList<string> columns, List<string[]> rows)
    {
        static string Q(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", columns.Select(Q)));
        foreach (var r in rows) sb.AppendLine(string.Join(",", r.Select(Q)));
        return sb.ToString();
    }

    // ───────────────────────────── XLSX ─────────────────────────────

    public static void SaveXlsx(string path, IReadOnlyList<string> columns, List<string[]> rows, string title)
    {
        using var fs = File.Create(path);
        using var zip = new ZipArchive(fs, ZipArchiveMode.Create);
        void Entry(string name, string content)
        {
            using var w = new StreamWriter(zip.CreateEntry(name, CompressionLevel.Optimal).Open(), new UTF8Encoding(false));
            w.Write(content);
        }
        Entry("[Content_Types].xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
            "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>" +
            "<Default Extension=\"xml\" ContentType=\"application/xml\"/>" +
            "<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>" +
            "<Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>" +
            "<Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>" +
            "<Override PartName=\"/docProps/core.xml\" ContentType=\"application/vnd.openxmlformats-package.core-properties+xml\"/>" +
            "</Types>");
        Entry("_rels/.rels",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
            "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>" +
            "<Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties\" Target=\"docProps/core.xml\"/>" +
            "</Relationships>");
        Entry("docProps/core.xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" " +
            "xmlns:dcterms=\"http://purl.org/dc/terms/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
            $"<dc:title>{X(title)}</dc:title><dc:creator>{X(AppInfo.Name + " – " + AppInfo.Company)}</dc:creator>" +
            $"<dcterms:created xsi:type=\"dcterms:W3CDTF\">{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ}</dcterms:created></cp:coreProperties>");
        Entry("xl/workbook.xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">" +
            "<sheets><sheet name=\"Devices\" sheetId=\"1\" r:id=\"rId1\"/></sheets>" +
            "<definedNames><definedName name=\"_xlnm._FilterDatabase\" localSheetId=\"0\" hidden=\"1\">" +
            $"Devices!$A$1:${Col(columns.Count - 1)}${rows.Count + 1}</definedName></definedNames></workbook>");
        Entry("xl/_rels/workbook.xml.rels",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
            "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>" +
            "<Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>" +
            "</Relationships>");
        // style 0 = normal, 1 = bold white on blue (header), 2 = orange fill (other subnet / behind NVR)
        Entry("xl/styles.xml",
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">" +
            "<fonts count=\"2\"><font><sz val=\"11\"/><name val=\"Calibri\"/></font><font><b/><sz val=\"11\"/><color rgb=\"FFFFFFFF\"/><name val=\"Calibri\"/></font></fonts>" +
            "<fills count=\"4\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill>" +
            "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FF0078D4\"/><bgColor indexed=\"64\"/></patternFill></fill>" +
            "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFFFF4E5\"/><bgColor indexed=\"64\"/></patternFill></fill></fills>" +
            "<borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders>" +
            "<cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>" +
            "<cellXfs count=\"3\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/>" +
            "<xf numFmtId=\"0\" fontId=\"1\" fillId=\"2\" borderId=\"0\" xfId=\"0\" applyFont=\"1\" applyFill=\"1\"/>" +
            "<xf numFmtId=\"0\" fontId=\"0\" fillId=\"3\" borderId=\"0\" xfId=\"0\" applyFill=\"1\"/></cellXfs>" +
            "<cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles></styleSheet>");

        var sb = new StringBuilder();
        sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
        sb.Append("<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">");
        sb.Append("<sheetViews><sheetView workbookViewId=\"0\"><pane ySplit=\"1\" topLeftCell=\"A2\" activePane=\"bottomLeft\" state=\"frozen\"/></sheetView></sheetViews>");
        sb.Append("<cols>");
        for (var c = 0; c < columns.Count; c++)
        {
            var width = Math.Clamp(Math.Max(columns[c].Length, rows.Count == 0 ? 0 : rows.Max(r => r[c].Length)) + 2, 8, 60);
            sb.Append($"<col min=\"{c + 1}\" max=\"{c + 1}\" width=\"{width}\" customWidth=\"1\"/>");
        }
        sb.Append("</cols><sheetData>");
        void Row(int r, IReadOnlyList<string> cells, int style)
        {
            sb.Append($"<row r=\"{r}\">");
            for (var c = 0; c < cells.Count; c++)
                sb.Append($"<c r=\"{Col(c)}{r}\" t=\"inlineStr\"{(style > 0 ? $" s=\"{style}\"" : "")}><is><t xml:space=\"preserve\">{X(cells[c])}</t></is></c>");
            sb.Append("</row>");
        }
        Row(1, columns, 1);
        for (var i = 0; i < rows.Count; i++)
        {
            var net = rows[i][7];
            Row(i + 2, rows[i], net.StartsWith("Other") || net.StartsWith("Behind NVR") ? 2 : 0);
        }
        sb.Append("</sheetData>");
        sb.Append($"<autoFilter ref=\"A1:{Col(columns.Count - 1)}{rows.Count + 1}\"/>");
        sb.Append("</worksheet>");
        Entry("xl/worksheets/sheet1.xml", sb.ToString());
    }

    /// <summary>0 → A, 25 → Z, 26 → AA.</summary>
    internal static string Col(int i)
    {
        var s = "";
        for (i++; i > 0; i = (i - 1) / 26) s = (char)('A' + (i - 1) % 26) + s;
        return s;
    }

    /// <summary>XML-escapes and drops characters XML does not allow.</summary>
    private static string X(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
        {
            if (ch < 0x20 && ch is not ('\t' or '\n' or '\r')) continue;
            sb.Append(ch switch { '&' => "&amp;", '<' => "&lt;", '>' => "&gt;", '"' => "&quot;", _ => ch.ToString() });
        }
        return sb.ToString();
    }

    // ───────────────────────────── HTML ─────────────────────────────

    public static string Html(IReadOnlyList<string> columns, List<string[]> rows, string title)
    {
        var sb = new StringBuilder();
        var types = rows.GroupBy(r => r[0]).OrderByDescending(g => g.Count()).Select(g => $"{WebUtility.HtmlEncode(g.Key)}: {g.Count()}");
        sb.Append("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.Append($"<title>{WebUtility.HtmlEncode(title)}</title><style>");
        sb.Append("body{font-family:'Segoe UI',Arial,sans-serif;margin:24px;color:#1b1b1b;background:#fff}h1{font-size:22px;margin:0 0 4px}" +
                  ".sub{color:#666;margin-bottom:14px}.chips span{display:inline-block;background:#eef4fb;border-radius:12px;padding:2px 10px;margin:2px 4px 2px 0;font-size:13px}" +
                  "table{border-collapse:collapse;width:100%;font-size:13px;margin-top:14px}th{background:#0078d4;color:#fff;text-align:left;padding:6px 8px;position:sticky;top:0}" +
                  "td{padding:5px 8px;border-bottom:1px solid #e6e6e6;vertical-align:top}tr.other td{background:#fff4e5}tr:hover td{background:#eaf3fc}" +
                  "td.bad{color:#b42318;font-weight:600}.foot{margin-top:16px;color:#888;font-size:12px}@media print{body{margin:8mm}th{position:static}tr{page-break-inside:avoid}}");
        sb.Append("</style></head><body>");
        sb.Append($"<h1>{WebUtility.HtmlEncode(title)}</h1>");
        sb.Append($"<div class=\"sub\">{rows.Count} devices · {DateTime.Now:yyyy-MM-dd HH:mm} · {WebUtility.HtmlEncode(AppInfo.Name)} {WebUtility.HtmlEncode(AppInfo.Version)} · © {WebUtility.HtmlEncode(AppInfo.Company)}</div>");
        sb.Append("<div class=\"chips\">");
        foreach (var t in types) sb.Append($"<span>{t}</span>");
        sb.Append("</div><table><thead><tr>");
        // the report keeps the columns people read; the Excel/CSV files have all of them
        // PC hardware columns (Windows, CPU, RAM, Disk, Graphics) only when some PC was read
        var show = new List<int> { 0, 1, 2, 3, 4, 6, 7, 9, 10, 11, 12 };
        foreach (var c in new[] { "Windows", "CPU", "RAM", "Disk", "Graphics", "Risky ports", "Watch status" })
        {
            var i = columns.ToList().IndexOf(c);
            if (i >= 0 && rows.Any(r => r[i].Length > 0)) show.Add(i);
        }
        foreach (var i in show) sb.Append($"<th>{WebUtility.HtmlEncode(columns[i])}</th>");
        sb.Append("</tr></thead><tbody>");
        foreach (var r in rows)
        {
            var other = r[7].StartsWith("Other") || r[7].StartsWith("Behind NVR");
            sb.Append(other ? "<tr class=\"other\">" : "<tr>");
            foreach (var i in show)
                sb.Append(columns[i] == "Risky ports" || (columns[i] == "Watch status" && r[i].StartsWith("Down"))
                    ? $"<td class=\"bad\">{WebUtility.HtmlEncode(r[i])}</td>" : $"<td>{WebUtility.HtmlEncode(r[i])}</td>");
            sb.Append("</tr>");
        }
        sb.Append("</tbody></table><div class=\"foot\">Orange rows: on another subnet or behind an NVR. Red: risky open ports, or a watched device that is down.</div>");
        sb.Append("</body></html>");
        return sb.ToString();
    }
}
