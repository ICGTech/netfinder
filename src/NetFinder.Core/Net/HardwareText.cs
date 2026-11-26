using System.Text.RegularExpressions;

namespace NetFinder.Core.Net;

/// <summary>Turns raw disk / graphics values into short readable text ("Samsung SSD 870 EVO (SSD, 500 GB)").</summary>
public static partial class HardwareText
{
    /// <summary>Disk sizes the way disk makers print them (decimal): 500 GB, 1 TB, 1.5 TB.</summary>
    public static string DiskSize(long bytes)
    {
        if (bytes <= 0) return "";
        var gb = bytes / 1e9;
        if (gb >= 1000) return $"{Math.Round(gb / 1000, gb >= 10000 ? 0 : 1):0.#} TB";
        // round to the size on the box: 499.9 GB → 500 GB, 256.06 GB → 256 GB
        return $"{Math.Round(gb):0} GB";
    }

    /// <summary>Memory sizes (binary): 512 MB, 2 GB, 8 GB.</summary>
    public static string MemorySize(long bytes)
    {
        if (bytes <= 0) return "";
        var mb = bytes / 1048576.0;
        return mb >= 1024 ? $"{Math.Round(mb / 1024, mb >= 10240 ? 0 : 1):0.#} GB" : $"{Math.Round(mb):0} MB";
    }

    /// <summary>"SSD", "NVMe SSD", "HDD" or null, from what Windows reports (MSFT_PhysicalDisk) or the model name.</summary>
    public static string? DiskKind(int? mediaType, int? busType, string? model)
    {
        var nvme = busType == 17 || (model?.Contains("nvme", StringComparison.OrdinalIgnoreCase) ?? false);
        if (mediaType == 4 || nvme || SsdRx().IsMatch(model ?? "")) return nvme ? "NVMe SSD" : "SSD";
        if (mediaType == 3) return "HDD";
        return HddRx().IsMatch(model ?? "") ? "HDD" : null;
    }

    /// <summary>One disk as Windows reports it. MediaType / BusType are MSFT_PhysicalDisk's (4 = SSD, 3 = HDD; bus 17 = NVMe).</summary>
    public sealed record DiskEntry(string Name, int? MediaType, int? BusType, long Size);

    public static string Disk(DiskEntry d) => Disk(d.Name, DiskKind(d.MediaType, d.BusType, d.Name), d.Size);

    /// <summary>
    /// The disks of <paramref name="main"/>, plus those of <paramref name="extra"/> that are not already there. Two disks of the
    /// same model in one PC both stay: each one of <paramref name="extra"/> can only match one of <paramref name="main"/>.
    /// Missing size / kind are taken from the matching entry.
    /// </summary>
    public static List<DiskEntry> MergeDisks(List<DiskEntry> main, List<DiskEntry> extra)
    {
        var res = main.Where(d => d.Name.Length > 0).ToList();
        var used = new bool[res.Count];
        foreach (var e in extra.Where(d => d.Name.Length > 0))
        {
            var i = Enumerable.Range(0, res.Count).FirstOrDefault(j => !used[j] && SameDisk(res[j].Name, e.Name), -1);
            if (i < 0) { res.Add(e); continue; }
            used[i] = true;
            var m = res[i];
            res[i] = m with { MediaType = m.MediaType is null or 0 ? e.MediaType : m.MediaType, BusType = m.BusType ?? e.BusType, Size = m.Size > 0 ? m.Size : e.Size };
        }
        return res;
    }

    /// <summary>Same disk model, written two ways ("NVMe Samsung SSD 970" / "Samsung SSD 970 EVO Plus 500GB").</summary>
    public static bool SameDisk(string a, string b)
    {
        string N(string x)
        {
            var t = Regex.Replace(x.ToUpperInvariant(), @"^(ATA|NVME|SCSI)\s+", "");
            return Regex.Replace(t, "[^A-Z0-9]", "");
        }
        string na = N(a), nb = N(b);
        var len = Math.Min(12, Math.Min(na.Length, nb.Length));
        return len >= 6 && string.CompareOrdinal(na, 0, nb, 0, len) == 0;
    }

    /// <summary>"ST1000DM003-1CH162 ATA Device" → "ST1000DM003-1CH162".</summary>
    public static string CleanDiskName(string name)
    {
        name = Regex.Replace(name.Replace('_', ' '), @"\s+", " ").Trim();
        return Regex.Replace(name, @"\s+(ATA|SCSI|NVMe|USB)?\s*(Disk\s+)?Device$", "", RegexOptions.IgnoreCase).Trim();
    }

    /// <summary>
    /// A disk's name in HARDWARE\DEVICEMAP\Scsi ("Identifier"): SCSI inquiry text, vendor (8) + product (16) + revision (4),
    /// e.g. "ATA     ST1000DM010-2EP1CC43" or "NVMe    Samsung SSD 970 2B2Q". The revision is dropped.
    /// </summary>
    public static string DiskFromScsiIdentifier(string id)
    {
        id = id.TrimEnd('\0');
        if (id.Length >= 24 && id.Length <= 28 && id[..8].TrimEnd().Length < 8 + 1)
        {
            var vendor = id[..8].Trim();
            var product = id.Substring(8, 16).Trim();
            if (product.Length > 0)
                return CleanDiskName((vendor.Length == 0 || vendor is "ATA" || vendor.Equals("NVMe", StringComparison.OrdinalIgnoreCase) ? "" : vendor + " ") + product);
        }
        return CleanDiskName(Regex.Replace(id, @"^(ATA|NVMe)\s+", "", RegexOptions.IgnoreCase));
    }

    /// <summary>
    /// A disk's size read from its model name, for when Windows gave none (the registry has no sizes): makers put the
    /// capacity in the name ("WD2002FYPS" = 2 TB, "ST1000DM010" = 1 TB, "KINGSTON SA400S37480G" = 480 GB). 0 when unsure.
    /// </summary>
    public static long SizeFromModel(string model)
    {
        var m = Regex.Replace(model.ToUpperInvariant().Replace('_', ' '), @"\s+", " ").Trim();
        m = Regex.Replace(m, @"^(ATA|NVME|SCSI) ", "");
        const long G = 1_000_000_000, T = 1_000_000_000_000;
        Match x;
        // written out: "Samsung SSD 860 EVO 500GB", "Portable 1TB", "2 TB"
        if ((x = Regex.Match(m, @"(?<![\w.])(\d{1,2}(?:\.\d)?) ?TB\b")).Success) return (long)(double.Parse(x.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) * T);
        if ((x = Regex.Match(m, @"(?<![\w.])(\d{2,4}) ?GB\b")).Success) return long.Parse(x.Groups[1].Value) * G;
        // Western Digital SSD: WDS500G2B0A = 500 GB, WDS100T2B0A = 1 TB
        if ((x = Regex.Match(m, @"\bWDS(\d{3})([GT])")).Success) return x.Groups[2].Value == "G" ? long.Parse(x.Groups[1].Value) * G : long.Parse(x.Groups[1].Value) * T / 100;
        // Western Digital disk: WD10EZEX = 1 TB, WD20EZRZ = 2 TB, WD5000AAKX = 500 GB, WD2002FYPS = 2 TB, WD100EFAX = 10 TB
        if ((x = Regex.Match(m, @"^(?:WDC )?WD(\d{2,4})[A-Z]{2}")).Success)
        {
            var d = x.Groups[1].Value; var n = int.Parse(d);
            if (d.Length == 2) return n * T / 10;
            if (d.Length == 3) return n is >= 100 and <= 240 ? n * T / 10 : 0;
            if (n % 100 == 0) return n / 10 * G;          // 5000 → 500 GB, 3200 → 320 GB
            if (n % 1000 < 10) return n / 1000 * T;       // 1002 → 1 TB, 2002 → 2 TB, 4003 → 4 TB
            return 0;
        }
        // Seagate: ST1000DM010 = 1000 GB, ST500LM030 = 500 GB; older ST3500418AS = 500 GB, ST31000524AS = 1000 GB
        if ((x = Regex.Match(m, @"^ST(\d{3,5})[A-Z]{2}\d")).Success) return long.Parse(x.Groups[1].Value) * G;
        if ((x = Regex.Match(m, @"^ST[39](\d{2,5})(\d{3})[A-Z]{1,3}\b")).Success) return long.Parse(x.Groups[1].Value) * G;
        // Toshiba: DT01ACA100 = 1 TB, DT01ACA050 = 500 GB, MQ01ABD100 = 1 TB, HDWD120 = 2 TB
        if ((x = Regex.Match(m, @"^(?:TOSHIBA )?(?:DT01ACA|MQ0\dAB[A-Z])(\d{3})\b")).Success) return long.Parse(x.Groups[1].Value) * T / 100;
        if ((x = Regex.Match(m, @"^(?:TOSHIBA )?HDW[A-Z]1(\d)0\b")).Success) return long.Parse(x.Groups[1].Value) * T;
        // Samsung OEM SSD: MZ7LN256HAJQ = 256 GB, MZVLB512HBJQ = 512 GB, MZVLW1T0 = 1 TB
        if ((x = Regex.Match(m, @"^(?:SAMSUNG )?MZ[0-9A-Z]{3}(\d{3}|\dT\d)")).Success)
            return x.Groups[1].Value.Contains('T') ? (x.Groups[1].Value[0] - '0') * T : long.Parse(x.Groups[1].Value) * G;
        // Crucial CT500MX500SSD1 = 500 GB; SK hynix HFS256G… / HFM512G…; Intel SSDSC2KW256G8; Toshiba THNSN…256G…, KBG40ZNS256G
        if ((x = Regex.Match(m, @"^(?:CRUCIAL )?CT(\d{3,4})(?:MX|BX|P\d|T\d)")).Success) return long.Parse(x.Groups[1].Value) * G;
        if ((x = Regex.Match(m, @"^(?:SK ?HYNIX )?HF[SM](\d{3})G")).Success) return long.Parse(x.Groups[1].Value) * G;
        if ((x = Regex.Match(m, @"^(?:INTEL )?SSD(?:SC|PE)\w{3}(\d{3})G")).Success) return long.Parse(x.Groups[1].Value) * G;
        if ((x = Regex.Match(m, @"^(?:TOSHIBA |KIOXIA )?(?:THNSN\w|KBG\w{5})(\d{3})G")).Success) return long.Parse(x.Groups[1].Value) * G;
        // ends in the size: KINGSTON SA400S37480G = 480 GB, SNV2S1000G = 1000 GB
        if ((x = Regex.Match(m, @"(?:S37|[A-Z])(\d{3,4})G$")).Success) return long.Parse(x.Groups[1].Value) * G;
        return 0;
    }

    /// <summary>"Samsung SSD 870 EVO 500GB (SSD, 500 GB)". With no size from Windows, the size in the model name is used.</summary>
    public static string Disk(string model, string? kind, long size)
    {
        model = Regex.Replace(model.Replace('_', ' '), @"\s+", " ").Trim();
        // no size from Windows: the one in the model name, unless the name already shows it ("… 500GB")
        if (size <= 0 && !Regex.IsMatch(model, @"\d ?[GT]B\b", RegexOptions.IgnoreCase)) size = SizeFromModel(model);
        var parts = new List<string>();
        if (kind != null && !model.Contains(kind, StringComparison.OrdinalIgnoreCase)) parts.Add(kind);
        var sz = DiskSize(size);
        if (sz.Length > 0) parts.Add(sz);
        return parts.Count == 0 ? model : $"{model} ({string.Join(", ", parts)})";
    }

    public static string Gpu(string name, long vram) =>
        vram > 0 ? $"{name.Trim()} ({MemorySize(vram)})" : name.Trim();

    /// <summary>Display drivers that are not a graphics card: remote desktop, mirror and virtual-monitor drivers.</summary>
    public static bool IsSoftwareDisplay(string name) => SoftwareDisplayRx().IsMatch(name);

    /// <summary>"Microsoft Basic Display Adapter" means "no driver installed": keep it only when it is the only one.</summary>
    public static bool IsBasicDisplay(string name) => name.Contains("Basic Display", StringComparison.OrdinalIgnoreCase);

    /// <summary>Instance path of a disk ("SCSI\Disk&amp;Ven_NVMe&amp;Prod_Samsung_SSD_970\…") → "NVMe Samsung SSD 970"; null for USB sticks.</summary>
    public static string? DiskFromInstance(string instance)
    {
        if (instance.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase) || instance.StartsWith("SD\\", StringComparison.OrdinalIgnoreCase)) return null;
        var id = instance.Split('\\') is { Length: > 1 } p ? p[1] : instance;
        var ven = Regex.Match(id, @"Ven_([^&]*)", RegexOptions.IgnoreCase).Groups[1].Value;
        var prod = Regex.Match(id, @"Prod_([^&]*)", RegexOptions.IgnoreCase).Groups[1].Value;
        string name;
        if (prod.Length > 0) name = (ven.Length > 0 && !ven.Equals("ATA", StringComparison.OrdinalIgnoreCase) ? ven + " " : "") + prod;
        else name = Regex.Replace(id, @"^Disk", "", RegexOptions.IgnoreCase);
        name = Regex.Replace(name.Replace('_', ' '), @"\s+", " ").Trim();
        return name.Length == 0 ? null : name;
    }

    // SSDs whose name does not say "SSD": Samsung OEM (MZ7…, MZV…), SK hynix, Kingston A400, Crucial, WD Blue/Green SSD (WDS…), Intel, Toshiba/Kioxia OEM…
    [GeneratedRegex(@"\bssd\b|solid state|\bnvme\b|\bm\.2\b|^(samsung )?mz[0-9a-z]{2}|^sk ?hynix|^hfs\d|^h[bc]s\d|^liteon (cv|ca|l8|cl)|^lite-on|^kingston (s|a400|om|rbu)|\bsa400|^ct\d+(mx|bx|p\d)|crucial|^intel (ssd|hb)|^ssdsc|^ssdpe|^thnsn|^kbg|^kxg|^toshiba thn|^kioxia|\bpc sn\d|\bsn\d{3}\b|\bwds\d|^wd (blue|green|black|red) sn|^pny cs|^adata (su|sx|im)|^lexar|^micron|^ssstc|^cl\d+ nvme|^hp ssd|^apacer|^transcend ts\d+g(ssd|mte|mts)|^teamgroup|^team t|^netac|^hikvision|^goodram|^patriot|^silicon power|^sp\d+gbss|^biwin|^kimtigo|^gigabyte gp|^ramsta|^fikwot", RegexOptions.IgnoreCase)]
    private static partial Regex SsdRx();
    [GeneratedRegex(@"^(st\d|wdc wd\d|wd\d{3,}|hgst|toshiba (dt|mq|hdw|md|al)|hitachi|hts\d|hds\d|hua\d|hus\d|mb\d{3,}|mm\d{3,}|apple hdd|samsung (hd|hn|sp)\d|maxtor|fujitsu mh)", RegexOptions.IgnoreCase)]
    private static partial Regex HddRx();
    [GeneratedRegex(@"remote display|basic render|mirror|indirect display|virtual display|virtual monitor|dameware|radmin|citrix|splashtop|parsec|spacedesk|teamviewer|anydesk|\bidd\b|displaylink", RegexOptions.IgnoreCase)]
    private static partial Regex SoftwareDisplayRx();
}
