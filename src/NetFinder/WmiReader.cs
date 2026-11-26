using System.Management;
using System.Runtime.InteropServices;
using NetFinder.Core.Model;

namespace NetFinder;

/// <summary>What Windows itself reports about a PC (WMI).</summary>
public sealed record PcInfo(string? Manufacturer, string? Model, string? Serial, string? ComputerName, string? Domain, string? Windows,
    string? Cpu, long? RamBytes, string? LoggedInUser, string? Bios)
{
    /// <summary>Applies it to a device row (call inside DeviceStore.Touch).</summary>
    public void ApplyTo(Device d)
    {
        d.Sources.Add("WMI");
        d.OfferModel(Model, "Windows (WMI)", 100);
        if (Manufacturer != null) { d.Info["Manufacturer"] = Manufacturer; d.Vendor ??= Manufacturer; }
        if (Serial != null) d.Info["Serial number"] = Serial;
        if (ComputerName != null) { d.Info["Computer name"] = ComputerName; d.Hostname ??= ComputerName; }
        if (Domain != null) d.Info["Workgroup / domain"] = Domain;
        if (Windows != null) d.Info["Windows"] = Windows;
        if (Cpu != null) d.Info["CPU"] = Cpu;
        if (RamBytes is > 0) d.Info["RAM"] = $"{Math.Round(RamBytes.Value / 1073741824.0)} GB";
        if (LoggedInUser != null) d.Info["Logged-in user"] = LoggedInUser;
        if (Bios != null) d.Info["BIOS"] = Bios;
    }
}

/// <summary>
/// Reads model, serial number, CPU, RAM and Windows version of a Windows PC over WMI (DCOM, TCP 135 + dynamic ports).
/// Needs an account that is administrator on that PC (a domain admin, or the PC's own admin account).
/// Credentials are only used for the call; nothing is stored.
/// </summary>
public static class WmiReader
{
    public static Task<PcInfo> ReadAsync(string host, string? user, string? password, bool local, CancellationToken ct) =>
        Task.Run(() => Read(host, user, password, local), ct);

    private static PcInfo Read(string host, string? user, string? password, bool local)
    {
        var opt = new ConnectionOptions
        {
            Impersonation = ImpersonationLevel.Impersonate,
            Authentication = AuthenticationLevel.PacketPrivacy,
            Timeout = TimeSpan.FromSeconds(20),
            EnablePrivileges = true,
        };
        // Windows refuses a user name for the local PC ("User credentials cannot be used for local connections")
        if (!local && !string.IsNullOrWhiteSpace(user)) { opt.Username = user.Trim(); opt.Password = password; }
        var scope = new ManagementScope(local ? @"\\.\root\cimv2" : $@"\\{host}\root\cimv2", opt);
        try { scope.Connect(); }
        catch (Exception ex) { throw new InvalidOperationException(Explain(ex, host), ex); }

        Dictionary<string, string> One(string cls, params string[] props)
        {
            var res = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var s = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT {string.Join(",", props)} FROM {cls}"),
                    new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(20), ReturnImmediately = false });
                foreach (var o in s.Get())
                {
                    using (o)
                        foreach (var p in props)
                            if (!res.ContainsKey(p) && o[p]?.ToString()?.Trim() is { Length: > 0 } v) res[p] = v;
                }
            }
            catch (ManagementException) { }
            return res;
        }

        var cs = One("Win32_ComputerSystem", "Manufacturer", "Model", "Name", "Domain", "UserName", "TotalPhysicalMemory");
        var prod = One("Win32_ComputerSystemProduct", "Version", "IdentifyingNumber");
        var bios = One("Win32_BIOS", "SerialNumber", "SMBIOSBIOSVersion");
        var os = One("Win32_OperatingSystem", "Caption", "Version");
        var cpu = One("Win32_Processor", "Name");

        var maker = Clean(cs.GetValueOrDefault("Manufacturer"));
        var model = Clean(cs.GetValueOrDefault("Model"));
        // Lenovo keeps the marketing name ("ThinkPad T14 Gen 2") in ComputerSystemProduct.Version, the model has the machine type
        if (maker?.Contains("lenovo", StringComparison.OrdinalIgnoreCase) == true && Clean(prod.GetValueOrDefault("Version")) is { } lv && !lv.Equals(model, StringComparison.OrdinalIgnoreCase))
            model = model == null ? lv : $"{lv} ({model})";
        // Self-built PC: name the motherboard instead
        if (maker == null || model == null)
        {
            var board = One("Win32_BaseBoard", "Manufacturer", "Product");
            var bm = Clean(board.GetValueOrDefault("Manufacturer"));
            var bp = Clean(board.GetValueOrDefault("Product"));
            if (bp != null) { model = $"Custom PC ({bm} {bp})".Replace("( ", "(").Trim(); maker ??= bm; }
        }
        // "OptiPlex 7090" → "Dell OptiPlex 7090" (HP and Lenovo already carry the brand)
        var brand = maker?.Split(' ', ',')[0];
        if (brand is { Length: > 1 } && model != null && !model.StartsWith("Custom PC") && !model.Contains(brand, StringComparison.OrdinalIgnoreCase))
            model = (brand.All(char.IsUpper) && brand.Length > 3 ? brand[0] + brand[1..].ToLowerInvariant() : brand) + " " + model;
        var serial = Clean(bios.GetValueOrDefault("SerialNumber")) ?? Clean(prod.GetValueOrDefault("IdentifyingNumber"));
        var windows = os.GetValueOrDefault("Caption") is { } cap ? cap.Replace("Microsoft ", "") + (os.GetValueOrDefault("Version") is { } v ? $" ({v})" : "") : null;
        long? ram = long.TryParse(cs.GetValueOrDefault("TotalPhysicalMemory"), out var r) ? r : null;
        return new PcInfo(maker, model, serial, cs.GetValueOrDefault("Name"), cs.GetValueOrDefault("Domain"), windows,
            cpu.GetValueOrDefault("Name") is { } c ? System.Text.RegularExpressions.Regex.Replace(c, @"\s+", " ") : null, ram,
            cs.GetValueOrDefault("UserName"), bios.GetValueOrDefault("SMBIOSBIOSVersion"));
    }

    /// <summary>Drops the placeholders OEMs leave in the firmware.</summary>
    private static string? Clean(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        v = v.Trim();
        var junk = new[] { "To be filled by O.E.M.", "To Be Filled By O.E.M.", "System manufacturer", "System Product Name", "Default string", "OEM", "Not Applicable", "None", "0", "System Serial Number", "Not Specified", "INVALID" };
        return junk.Any(j => v.Equals(j, StringComparison.OrdinalIgnoreCase)) ? null : v;
    }

    private static string Explain(Exception ex, string host)
    {
        var hr = ex is COMException ce ? ce.HResult : ex.HResult;
        if (ex is UnauthorizedAccessException || hr == unchecked((int)0x80070005))
            return $"Access denied on {host}. Use an account that is administrator on that PC (e.g. DOMAIN\\admin, or {host}\\Administrator).\n\n" +
                   "With a local (non-domain) account, Windows 10/11 blocks remote admin access unless it is the built-in Administrator " +
                   "or the PC has LocalAccountTokenFilterPolicy=1.";
        if (hr == unchecked((int)0x800706BA) || hr == unchecked((int)0x800706BE))
            return $"{host} did not answer WMI (the RPC server is unavailable): it is off, it is not Windows, or its firewall blocks remote management.\n\n" +
                   "On that PC: Windows Defender Firewall → Allow an app → tick \"Windows Management Instrumentation (WMI)\".";
        if (hr == unchecked((int)0x8007052E) || ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase))
            return $"Wrong user name or password for {host}.";
        return $"WMI on {host}: {ex.Message}";
    }
}
