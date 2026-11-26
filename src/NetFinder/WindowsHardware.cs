using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using NetFinder.Core.Net;

namespace NetFinder;

/// <summary>Read-only view of a PC's HKEY_LOCAL_MACHINE, over the Remote Registry or over WMI (StdRegProv).</summary>
internal interface IRegView
{
    string[] SubKeys(string path);
    string[] ValueNames(string path);
    object? Value(string path, string name);
}

internal sealed class RemoteRegView(RegistryKey hklm) : IRegView
{
    public string[] SubKeys(string path) => Try(path, k => k.GetSubKeyNames()) ?? Array.Empty<string>();
    public string[] ValueNames(string path) => Try(path, k => k.GetValueNames()) ?? Array.Empty<string>();
    public object? Value(string path, string name) => Try<object>(path, k => k.GetValue(name));

    private T? Try<T>(string path, Func<RegistryKey, T?> f) where T : class
    {
        try { using var k = hklm.OpenSubKey(path); return k == null ? null : f(k); }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }
}

/// <summary>The registry through WMI's StdRegProv: works wherever WMI works, no Remote Registry service needed.</summary>
internal sealed class WmiRegView : IRegView, IDisposable
{
    private const uint Hklm = 0x80000002;
    private readonly ManagementClass _reg;
    private readonly Dictionary<string, Dictionary<string, int>> _types = new(StringComparer.OrdinalIgnoreCase);

    public WmiRegView(ManagementScope scope) => _reg = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);

    private ManagementBaseObject? Call(string method, string path, string? name = null)
    {
        try
        {
            using var inp = _reg.GetMethodParameters(method);
            inp["hDefKey"] = Hklm;
            inp["sSubKeyName"] = path;
            if (name != null) inp["sValueName"] = name;
            var o = _reg.InvokeMethod(method, inp, null);
            return o != null && Convert.ToUInt32(o["ReturnValue"]) == 0 ? o : null;
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException) { return null; }
    }

    public string[] SubKeys(string path) => Call("EnumKey", path)?["sNames"] as string[] ?? Array.Empty<string>();

    private Dictionary<string, int> Types(string path)
    {
        if (_types.TryGetValue(path, out var t)) return t;
        t = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (Call("EnumValues", path) is { } o && o["sNames"] is string[] names && o["Types"] is int[] types)
            for (var i = 0; i < names.Length && i < types.Length; i++) t[names[i]] = types[i];
        return _types[path] = t;
    }

    public string[] ValueNames(string path) => Types(path).Keys.ToArray();

    public object? Value(string path, string name)
    {
        if (!Types(path).TryGetValue(name, out var type)) return null;
        return type switch
        {
            1 => Call("GetStringValue", path, name)?["sValue"],
            2 => Call("GetExpandedStringValue", path, name)?["sValue"],
            3 => Call("GetBinaryValue", path, name)?["uValue"],
            4 => Call("GetDWORDValue", path, name)?["uValue"],
            7 => Call("GetMultiStringValue", path, name)?["sValue"],
            11 => Call("GetQWORDValue", path, name)?["uValue"],
            _ => null,
        };
    }

    public void Dispose() => _reg.Dispose();
}

/// <summary>Disks, drive C: and graphics cards of a Windows PC.</summary>
internal static class WinHardware
{
    private const string VideoClass = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";

    /// <summary>
    /// The graphics cards in use: HKLM\HARDWARE\DEVICEMAP\VIDEO points at the active ones; their keys hold the name and the
    /// real video memory (HardwareInformation.qwMemorySize – WMI's AdapterRAM stops at 4 GB).
    /// </summary>
    public static List<(string Name, long Vram)> Gpus(IRegView r)
    {
        var keys = new List<string>();
        const string map = @"HARDWARE\DEVICEMAP\VIDEO";
        foreach (var n in r.ValueNames(map))
            if (n.StartsWith(@"\Device\Video", StringComparison.OrdinalIgnoreCase) && Str(r.Value(map, n)) is { } p)
            {
                var i = p.IndexOf(@"\Machine\", StringComparison.OrdinalIgnoreCase);
                if (i >= 0) keys.Add(p[(i + 9)..]);
            }
        var res = Read(keys);
        if (res.Count == 0) res = Read(r.SubKeys(VideoClass).Where(k => k.Length == 4 && k.All(char.IsDigit)).Select(k => VideoClass + "\\" + k));
        // "Microsoft Basic Display Adapter" = no driver: only worth showing when nothing else is there
        if (res.Any(g => !HardwareText.IsBasicDisplay(g.Name))) res.RemoveAll(g => HardwareText.IsBasicDisplay(g.Name));
        return res;

        List<(string Name, long Vram)> Read(IEnumerable<string> ks)
        {
            var list = new List<(string Name, long Vram)>();
            foreach (var k in ks.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var name = Str(r.Value(k, "DriverDesc")) ?? Str(r.Value(k, "HardwareInformation.AdapterString")) ?? Str(r.Value(k, "Device Description"));
                if (name == null || HardwareText.IsSoftwareDisplay(name)) continue;
                var vram = Num(r.Value(k, "HardwareInformation.qwMemorySize")) ?? Num(r.Value(k, "HardwareInformation.MemorySize")) ?? 0;
                var old = list.FindIndex(g => g.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (old < 0) list.Add((name, vram));
                else if (list[old].Vram == 0 && vram > 0) list[old] = (name, vram);
            }
            return list;
        }
    }

    /// <summary>
    /// Every internal disk named in the registry (no sizes there): the disk driver's device list (Services\disk\Enum)
    /// plus the storage controllers' map (HARDWARE\DEVICEMAP\Scsi, SATA and NVMe), so a second disk is never missed.
    /// USB disks are left out.
    /// </summary>
    public static List<string> Disks(IRegView r)
    {
        var fromEnum = new List<HardwareText.DiskEntry>();
        const string en = @"SYSTEM\CurrentControlSet\Services\disk\Enum";
        foreach (var n in r.ValueNames(en).Where(v => v.Length > 0 && v.All(char.IsDigit)).OrderBy(v => int.Parse(v)))
        {
            if (Str(r.Value(en, n)) is not { } inst || HardwareText.DiskFromInstance(inst) is not { } fromId) continue;
            var name = Str(r.Value(@"SYSTEM\CurrentControlSet\Enum\" + inst, "FriendlyName")) ?? fromId;
            fromEnum.Add(new(HardwareText.CleanDiskName(name), null, inst.Contains("NVMe", StringComparison.OrdinalIgnoreCase) ? 17 : null, 0));
        }
        var fromMap = new List<HardwareText.DiskEntry>();
        const string map = @"HARDWARE\DEVICEMAP\Scsi";
        foreach (var port in r.SubKeys(map))
        {
            var pk = map + "\\" + port;
            var driver = Str(r.Value(pk, "Driver")) ?? "";
            if (driver.Contains("usb", StringComparison.OrdinalIgnoreCase) || driver.Contains("uasp", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var bus in r.SubKeys(pk))
            foreach (var target in r.SubKeys(pk + "\\" + bus))
            foreach (var lun in r.SubKeys(pk + "\\" + bus + "\\" + target))
            {
                var lk = $@"{pk}\{bus}\{target}\{lun}";
                if (!string.Equals(Str(r.Value(lk, "Type")), "DiskPeripheral", StringComparison.OrdinalIgnoreCase)) continue;
                if (Str(r.Value(lk, "Identifier")) is { } id)
                    fromMap.Add(new(HardwareText.DiskFromScsiIdentifier(id), null, driver.Contains("nvme", StringComparison.OrdinalIgnoreCase) ? 17 : null, 0));
            }
        }
        return HardwareText.MergeDisks(fromEnum, fromMap).Select(HardwareText.Disk).ToList();
    }

    /// <summary>
    /// Disks over WMI: MSFT_PhysicalDisk knows SSD / HDD and the size (Windows 8 and later); Win32_DiskDrive fills in
    /// anything it left out (and is all there is on Windows 7). USB disks are left out.
    /// </summary>
    public static List<string> WmiDisks(string host, bool local, ConnectionOptions opt)
    {
        var storage = new List<HardwareText.DiskEntry>();
        try
        {
            var st = new ManagementScope(local ? @"\\.\root\Microsoft\Windows\Storage" : $@"\\{host}\root\Microsoft\Windows\Storage", opt);
            st.Connect();
            foreach (var d in Rows(st, "MSFT_PhysicalDisk", "FriendlyName", "MediaType", "BusType", "Size"))
            {
                var bus = Int(d.GetValueOrDefault("BusType"));
                if (bus is 7 or 12 or 13 /* USB, SD, MMC */ || Str(d.GetValueOrDefault("FriendlyName")) is not { } name) continue;
                storage.Add(new(HardwareText.CleanDiskName(name), Int(d.GetValueOrDefault("MediaType")), bus, Num(d.GetValueOrDefault("Size")) ?? 0));
            }
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException) { }
        var classic = new List<HardwareText.DiskEntry>();
        try
        {
            var cs = new ManagementScope(local ? @"\\.\root\cimv2" : $@"\\{host}\root\cimv2", opt);
            foreach (var d in Rows(cs, "Win32_DiskDrive", "Model", "Size", "InterfaceType", "MediaType", "PNPDeviceID"))
            {
                // A second SATA disk on a hot-plug port says "External hard disk media" (or "Removable"): it is still inside the PC.
                // Only USB disks and card readers are left out.
                var media = Str(d.GetValueOrDefault("MediaType")) ?? "";
                var pnp = Str(d.GetValueOrDefault("PNPDeviceID")) ?? "";
                var size = Num(d.GetValueOrDefault("Size")) ?? 0;
                if (Str(d.GetValueOrDefault("InterfaceType")) == "USB" || pnp.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase) ||
                    pnp.StartsWith(@"SD\", StringComparison.OrdinalIgnoreCase) || (media.Contains("Removable", StringComparison.OrdinalIgnoreCase) && size == 0) ||
                    Str(d.GetValueOrDefault("Model")) is not { } name) continue;
                classic.Add(new(HardwareText.CleanDiskName(name), null, pnp.StartsWith("NVME", StringComparison.OrdinalIgnoreCase) || pnp.Contains("NVMe", StringComparison.OrdinalIgnoreCase) ? 17 : null, size));
            }
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException) { }
        return HardwareText.MergeDisks(storage, classic).Select(HardwareText.Disk).ToList();
    }

    /// <summary>Graphics over WMI: names from Win32_VideoController, real memory from the registry through StdRegProv.</summary>
    public static List<(string Name, long Vram)> WmiGpus(ManagementScope scope)
    {
        var fromReg = new List<(string Name, long Vram)>();
        try { using var reg = new WmiRegView(scope); fromReg = Gpus(reg); }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException) { }
        var res = new List<(string Name, long Vram)>();
        try
        {
            foreach (var v in Rows(scope, "Win32_VideoController", "Name", "AdapterRAM"))
            {
                if (Str(v.GetValueOrDefault("Name")) is not { } name || HardwareText.IsSoftwareDisplay(name)) continue;
                var ram = Num(v.GetValueOrDefault("AdapterRAM")) ?? 0;
                if (ram >= 0xFFF00000L) ram = 0; // 32-bit value: 4 GB and more can't be told apart
                var reg = fromReg.FirstOrDefault(g => g.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (res.All(g => !g.Name.Equals(name, StringComparison.OrdinalIgnoreCase))) res.Add((name, reg.Vram > 0 ? reg.Vram : ram));
            }
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException) { }
        if (res.Count == 0) res = fromReg;
        if (res.Any(g => !HardwareText.IsBasicDisplay(g.Name))) res.RemoveAll(g => HardwareText.IsBasicDisplay(g.Name));
        return res;
    }

    /// <summary>"476 GB (120 GB free)" – sizes the way Explorer shows them.</summary>
    public static string? Drive(long size, long free) =>
        size <= 0 ? null : $"{HardwareText.MemorySize(size)} ({HardwareText.MemorySize(free)} free)";

    /// <summary>
    /// Every drive letter of the PC with its size and free space, over SMB admin shares (\\pc\D$), with the SMB login already open.
    /// The letters come from the registry (MountedDevices); a letter without an admin share (DVD, a USB stick seen once) is skipped.
    /// </summary>
    public static string? DrivesOverSmb(string host, IRegView? r)
    {
        var letters = new SortedSet<char> { 'C' };
        try
        {
            if (r != null)
                foreach (var n in r.ValueNames(@"SYSTEM\MountedDevices"))
                    if (n.Length == 14 && n.StartsWith(@"\DosDevices\", StringComparison.OrdinalIgnoreCase) && n[13] == ':' && char.ToUpperInvariant(n[12]) is var l and >= 'C' and <= 'Z')
                        letters.Add(l);
        }
        catch { }
        var res = new List<string>();
        foreach (var l in letters)
        {
            try { if (GetDiskFreeSpaceEx($@"\\{host}\{l}$\", out _, out var total, out var free) && Drive((long)total, (long)free) is { } t) res.Add($"{l}: {t}"); }
            catch { }
        }
        return Join(res);
    }

    /// <summary>Every local hard-disk drive (C:, D:…) over WMI, with size and free space.</summary>
    public static string? WmiDrives(ManagementScope scope)
    {
        var res = new List<string>();
        foreach (var c in Rows(scope, "Win32_LogicalDisk WHERE DriveType=3", "DeviceID", "Size", "FreeSpace").OrderBy(c => Str(c.GetValueOrDefault("DeviceID"))))
            if (Str(c.GetValueOrDefault("DeviceID")) is { } id && Drive(Num(c.GetValueOrDefault("Size")) ?? 0, Num(c.GetValueOrDefault("FreeSpace")) ?? 0) is { } t)
                res.Add($"{id} {t}");
        return Join(res);
    }

    public static string? Join(IEnumerable<string> items)
    {
        var l = items.Where(i => !string.IsNullOrWhiteSpace(i)).ToList();
        return l.Count == 0 ? null : string.Join("  +  ", l);
    }

    public static string? JoinGpus(List<(string Name, long Vram)> gpus) => Join(gpus.Select(g => HardwareText.Gpu(g.Name, g.Vram)));

    internal static List<Dictionary<string, object?>> Rows(ManagementScope scope, string cls, params string[] props)
    {
        var res = new List<Dictionary<string, object?>>();
        using var s = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT {string.Join(",", props)} FROM {cls}"),
            new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(20), ReturnImmediately = false });
        foreach (var o in s.Get())
            using (o)
            {
                var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                foreach (var p in props) row[p] = o[p];
                res.Add(row);
            }
        return res;
    }

    internal static string? Str(object? v) => v switch
    {
        string s => s.Trim().TrimEnd('\0').Trim() is { Length: > 0 } t ? t : null,
        string[] many => many.Select(x => x.Trim()).FirstOrDefault(x => x.Length > 0),
        byte[] b when b.Length >= 2 => Encoding.Unicode.GetString(b).TrimEnd('\0').Trim() is { Length: > 0 } t ? t : null,
        _ => null,
    };

    internal static long? Num(object? v) => v switch
    {
        null => null,
        byte[] { Length: 8 } b => BitConverter.ToInt64(b, 0),
        byte[] { Length: 4 } b => BitConverter.ToUInt32(b, 0),
        byte[] => null,
        string s => long.TryParse(s, out var n) ? n : null,
        int i => (uint)i, // REG_DWORD comes back signed from RegistryKey
        IConvertible c => Convert.ToInt64(c),
        _ => null,
    };

    private static int? Int(object? v) => v is IConvertible c ? Convert.ToInt32(c) : null;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetDiskFreeSpaceExW")]
    private static extern bool GetDiskFreeSpaceEx(string dir, out ulong freeToCaller, out ulong total, out ulong totalFree);
}
