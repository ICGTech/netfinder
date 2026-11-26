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

    /// <summary>"Samsung SSD 870 EVO 500GB (SSD, 500 GB)". Drops the size when the name already says it.</summary>
    public static string Disk(string model, string? kind, long size)
    {
        model = Regex.Replace(model.Replace('_', ' '), @"\s+", " ").Trim();
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

    [GeneratedRegex(@"\bssd\b|solid state|\bnvme\b|\bm\.2\b", RegexOptions.IgnoreCase)]
    private static partial Regex SsdRx();
    [GeneratedRegex(@"^(st\d|wdc wd\d|wd\d|hgst|toshiba (dt|mq|hdw)|hitachi|hts\d|hds\d)", RegexOptions.IgnoreCase)]
    private static partial Regex HddRx();
    [GeneratedRegex(@"remote display|basic render|mirror|indirect display|virtual display|virtual monitor|dameware|radmin|citrix|splashtop|parsec|spacedesk|teamviewer|anydesk|\bidd\b|displaylink", RegexOptions.IgnoreCase)]
    private static partial Regex SoftwareDisplayRx();
}
