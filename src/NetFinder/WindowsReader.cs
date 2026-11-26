using System.ComponentModel;
using System.Management;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using NetFinder.Core;
using NetFinder.Core.Model;

namespace NetFinder;

/// <summary>What Windows itself reports about a PC (WMI or Remote Registry).</summary>
public sealed record PcInfo(string? Manufacturer, string? Model, string? Serial, string? ComputerName, string? Domain, string? Windows,
    string? Cpu, long? RamBytes, string? LoggedInUser, string? Bios, string Via, string? Disks = null, string? Drives = null, string? Graphics = null)
{
    /// <summary>Applies it to a device row (call inside DeviceStore.Touch).</summary>
    public void ApplyTo(Device d)
    {
        d.Sources.Add(Via);
        d.OfferModel(Model, $"Windows ({Via})", 100);
        if (Manufacturer != null) { d.Info["Manufacturer"] = Manufacturer; d.Vendor ??= Manufacturer; }
        if (Serial != null) d.Info["Serial number"] = Serial;
        if (ComputerName != null)
        {
            d.Info["Computer name"] = ComputerName;
            // a wrong passive name ("*", the domain name…) gives way to what Windows says
            if (d.Hostname == null || d.Hostname == "*" || (Domain != null && d.Hostname.Equals(Domain.Split('.')[0], StringComparison.OrdinalIgnoreCase)))
                d.Hostname = ComputerName;
        }
        if (Domain != null) d.Info["Workgroup / domain"] = Domain;
        if (Windows != null) d.Info["Windows"] = Windows;
        if (Cpu != null) d.Info["CPU"] = Cpu;
        if (RamBytes is > 0) d.Info["RAM"] = $"{Math.Round(RamBytes.Value / 1073741824.0)} GB";
        if (Disks != null) d.Info["Disk"] = Disks;
        if (Drives != null) { d.Info["Drives"] = Drives; d.Info.Remove("Drive C:"); }
        if (Graphics != null) d.Info["Graphics"] = Graphics;
        if (LoggedInUser != null) d.Info["Logged-in user"] = LoggedInUser;
        if (Bios != null) d.Info["BIOS"] = Bios;
    }
}

/// <summary>Why a PC could not be read. The UI counts them to give one clear summary.</summary>
public enum WinFail { Closed, Blocked, AccessDenied, NotAdmin, BadLogin, Other }

public sealed class WinReadException : Exception
{
    public WinFail Kind { get; }
    public WinReadException(WinFail kind, string message, Exception? inner = null) : base(message, inner) => Kind = kind;
}

/// <summary>
/// One Windows login used for many PCs ("Get models"). Works out which spelling of the user name Windows accepts
/// (ALMADA\admin, admin@almada.local, almada.local\admin…) and stops as soon as the password is known to be wrong,
/// so dozens of failed logons do not lock the account. Nothing is stored.
/// </summary>
public sealed class WindowsLoginSession
{
    /// <summary>null = the Windows account running NetFinder.</summary>
    public string? User { get; }
    public string? Password { get; }
    public IReadOnlyList<string?> Spellings { get; }
    /// <summary>Set when the Windows part must stop (wrong password, locked/disabled account).</summary>
    public string? StopReason { get; private set; }
    /// <summary>The spelling that logged in somewhere (or the only one there is).</summary>
    public string? Working => _working;
    public bool Confirmed => _confirmed;

    private string? _working;
    private bool _confirmed;
    private readonly HashSet<string> _deniedHosts = new();
    private readonly HashSet<string> _refused = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly Action<string> _log;

    public WindowsLoginSession(string? user, string? password, string? netbiosDomainHint, Action<string> log)
    {
        User = string.IsNullOrWhiteSpace(user) ? null : user.Trim();
        Password = password;
        _log = log;
        Spellings = User == null ? new string?[] { null } : UserSpellings(User, netbiosDomainHint).Cast<string?>().ToList();
        if (Spellings.Count == 1) _working = Spellings[0];
    }

    /// <summary>The spellings to try on the next PC.</summary>
    internal IReadOnlyList<string?> ToTry =>
        _confirmed ? new[] { _working } : _deniedHosts.Count > 0 ? Spellings.Take(1).ToList() : Spellings.Where(s => s == null || !_refused.Contains(s)).ToList();

    public static List<string> UserSpellings(string user, string? netbiosDomainHint = null) => Core.Net.WindowsNames.UserSpellings(user, netbiosDomainHint);

    /// <summary>
    /// Checks the login once over SMB (\\pc\IPC$, any domain PC accepts a valid login there): tells a wrong password
    /// apart from "not an administrator". Each spelling is tried at most once per run.
    /// Returns false when this PC cannot tell (no SMB, already connected with another login…).
    /// </summary>
    public async Task<bool> CheckAsync(string host, CancellationToken ct)
    {
        if (User == null || _confirmed || StopReason != null) return true;
        await _lock.WaitAsync(ct);
        try
        {
            if (_confirmed || StopReason != null) return true;
            foreach (var s in Spellings)
            {
                if (s == null || _refused.Contains(s)) continue;
                var err = await WindowsReader.WithTimeout(() => Smb.Connect(host, "IPC$", s, Password), TimeSpan.FromSeconds(25), ct);
                if (err == 0)
                {
                    Smb.Disconnect(host, "IPC$");
                    _working = s; _confirmed = true;
                    _log($"Windows login: \"{s}\" is accepted (checked on {host})" +
                         (_refused.Count > 0 ? $"; refused: {string.Join(", ", _refused.Select(r => $"\"{r}\""))}" : ""));
                    return true;
                }
                if (Smb.IsBadLogin(err)) { _refused.Add(s); _log($"Windows login: \"{s}\" refused by {host} ({Smb.Text(err)})"); continue; }
                if (Smb.AccountProblem(err) is { } why) { Stop($"Windows refused the account \"{s}\": {why}."); return true; }
                _log($"Windows login: could not check it on {host} ({Smb.Text(err)}), trying another PC");
                return false;
            }
            if (_refused.Count == Spellings.Count)
                Stop($"Wrong user name or password: {host} refused {string.Join(", ", _refused.Select(r => $"\"{r}\""))}. " +
                     "Nothing else was tried, so the account does not get locked.");
            return true;
        }
        finally { _lock.Release(); }
    }

    internal void Worked(string? spelling)
    {
        if (_confirmed) return;
        _working = spelling; _confirmed = true;
        _log($"Windows login: \"{spelling ?? "(this PC's own login)"}\" works");
    }

    /// <summary>Every spelling got "access denied" on one PC while the login itself was never confirmed.</summary>
    internal void DeniedEverywhere(string host)
    {
        if (_confirmed || User == null) return;
        int n;
        lock (_deniedHosts) { _deniedHosts.Add(host); n = _deniedHosts.Count; }
        if (n >= 2 && StopReason == null)
            Stop($"Access denied on 2 PCs with every spelling of \"{User}\": the user name or password is probably wrong. " +
                 "Stopped here so the account does not get locked.");
    }

    /// <summary>May the Remote Registry service be started for a moment on PCs where it is off (it is put back afterwards)?</summary>
    public bool AllowServiceStart { get; init; } = true;

    private int _smbInsteadOfWmi;
    /// <summary>WMI was blocked on 2 PCs where SMB worked: the network blocks WMI, so start with SMB.</summary>
    internal bool PreferSmb => _smbInsteadOfWmi >= 2;
    internal void SmbWorkedWhereWmiBlocked() => Interlocked.Increment(ref _smbInsteadOfWmi);

    private void Stop(string why) { StopReason = why; _log(why); }
}

/// <summary>
/// Reads model, serial number, CPU, RAM and Windows version of a Windows PC:
/// 1) WMI over DCOM (TCP 135 + a dynamic port), 2) if WMI is blocked: the Remote Registry over SMB (TCP 445).
/// Needs an account that is administrator on that PC (a domain admin, or the PC's own admin account).
/// Credentials are only used for the call; nothing is stored.
/// </summary>
public static class WindowsReader
{
    private static readonly TimeSpan WmiTimeout = TimeSpan.FromSeconds(45);

    /// <param name="Note">Anything done on the PC to read it ("Remote Registry started for the read, then put back").</param>
    public sealed record Result(PcInfo Info, string Login, string? Note = null);

    public static async Task<Result> ReadAsync(string host, bool local, WindowsLoginSession login, CancellationToken ct)
    {
        if (local)
        {
            var me = await WithTimeout(() => Wmi(@".", null, null, true), WmiTimeout, ct);
            return new Result(me, "this PC");
        }
        if (login.StopReason != null) throw new WinReadException(WinFail.BadLogin, "skipped: " + login.StopReason);

        var ip = System.Net.IPAddress.Parse(host);
        var p135 = NetworkEngine.IsTcpOpenAsync(ip, 135, 2000, ct);
        var p445 = NetworkEngine.IsTcpOpenAsync(ip, 445, 2000, ct);
        bool rpc = await p135, smb = await p445;
        if (!rpc && !smb)
            throw new WinReadException(WinFail.Closed, "ports 135 and 445 are closed: its firewall blocks remote management (or it is not Windows)");

        // one check of the login over SMB first: a wrong password then stops everything after a single try
        if (smb && login.User != null && !login.Confirmed) await login.CheckAsync(host, ct);
        if (login.StopReason != null) throw new WinReadException(WinFail.BadLogin, "skipped: " + login.StopReason);

        WinReadException? wmiError = null, smbError = null;

        async Task<Result> ViaSmb()
        {
            var s = login.Working ?? login.ToTry.FirstOrDefault();
            var (info, note) = await WithTimeout(() => Registry(host, s, login.Password, login.AllowServiceStart), TimeSpan.FromSeconds(60), ct);
            login.Worked(s);
            return new Result(info, s ?? "own login", note);
        }

        // WMI was blocked on earlier PCs but SMB worked: go straight to SMB (saves ~45 s per PC)
        if (smb && login.PreferSmb)
        {
            try { return await ViaSmb(); }
            catch (WinReadException ex) when (ex.Kind != WinFail.BadLogin) { smbError = ex; }
        }

        if (rpc)
        {
            foreach (var s in login.ToTry)
            {
                try
                {
                    var info = await WithTimeout(() => Wmi(host, s, login.Password, false), WmiTimeout, ct);
                    login.Worked(s);
                    return new Result(info, s ?? "own login");
                }
                catch (WinReadException ex)
                {
                    wmiError = ex;
                    if (ex.Kind != WinFail.AccessDenied && ex.Kind != WinFail.BadLogin) break; // firewall etc.: another spelling won't help
                }
            }
            if (wmiError?.Kind is WinFail.AccessDenied or WinFail.BadLogin && !login.Confirmed) login.DeniedEverywhere(host);
        }
        else wmiError = new WinReadException(WinFail.Blocked, "WMI: port 135 is closed");

        if (smb && smbError == null && login.StopReason == null)
        {
            try
            {
                var r = await ViaSmb();
                if (wmiError?.Kind == WinFail.Blocked) login.SmbWorkedWhereWmiBlocked();
                return r;
            }
            catch (WinReadException ex)
            {
                smbError = ex;
                if (ex.Kind is WinFail.BadLogin or WinFail.AccessDenied && !login.Confirmed) login.DeniedEverywhere(host);
            }
        }
        if (wmiError == null) throw smbError ?? new WinReadException(WinFail.Other, "no way to read it");
        if (smbError == null) throw wmiError;
        // the most useful of the two reasons decides what the summary says
        var kind = smbError.Kind is WinFail.BadLogin or WinFail.NotAdmin || wmiError.Kind is WinFail.Other or WinFail.Blocked ? smbError.Kind : wmiError.Kind;
        throw new WinReadException(kind, $"{wmiError.Message}; SMB: {smbError.Message}");
    }

    // ───────────────────────────── WMI ─────────────────────────────

    private static PcInfo Wmi(string host, string? user, string? password, bool local)
    {
        var opt = new ConnectionOptions
        {
            Impersonation = ImpersonationLevel.Impersonate,
            Authentication = AuthenticationLevel.PacketPrivacy,
            Timeout = TimeSpan.FromSeconds(20),
            EnablePrivileges = true,
        };
        // Windows refuses a user name for the local PC ("User credentials cannot be used for local connections")
        if (!local && user != null) { opt.Username = user; opt.Password = password; }
        var scope = new ManagementScope(local ? @"\\.\root\cimv2" : $@"\\{host}\root\cimv2", opt);
        try
        {
            scope.Connect();

            Dictionary<string, string> One(string cls, bool required, params string[] props)
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
                catch (ManagementException) when (!required) { }
                return res;
            }

            var cs = One("Win32_ComputerSystem", true, "Manufacturer", "Model", "Name", "Domain", "UserName", "TotalPhysicalMemory");
            var prod = One("Win32_ComputerSystemProduct", false, "Version", "IdentifyingNumber");
            var bios = One("Win32_BIOS", false, "SerialNumber", "SMBIOSBIOSVersion");
            var os = One("Win32_OperatingSystem", false, "Caption", "Version");
            var cpu = One("Win32_Processor", false, "Name");
            var board = One("Win32_BaseBoard", false, "Manufacturer", "Product");
            if (cs.Count == 0 && os.Count == 0) throw new WinReadException(WinFail.Other, "WMI answered but returned nothing");
            // disks, drives (C:, D:…) and graphics: extras, a failure here never fails the read
            string? disks = null, drives = null, gpus = null;
            try { disks = WinHardware.Join(WinHardware.WmiDisks(host, local, opt)); } catch { }
            try { drives = WinHardware.WmiDrives(scope); } catch { }
            try { gpus = WinHardware.JoinGpus(WinHardware.WmiGpus(scope)); } catch { }
            return new RawPc
            {
                Disks = disks, Drives = drives, Graphics = gpus,
                Maker = cs.GetValueOrDefault("Manufacturer"), Model = cs.GetValueOrDefault("Model"), ProductVersion = prod.GetValueOrDefault("Version"),
                BoardMaker = board.GetValueOrDefault("Manufacturer"), BoardProduct = board.GetValueOrDefault("Product"),
                Serial = Clean(bios.GetValueOrDefault("SerialNumber")) ?? Clean(prod.GetValueOrDefault("IdentifyingNumber")),
                Name = cs.GetValueOrDefault("Name"), Domain = cs.GetValueOrDefault("Domain"),
                Windows = os.GetValueOrDefault("Caption") is { } cap ? cap.Replace("Microsoft ", "") + (os.GetValueOrDefault("Version") is { } v ? $" ({v})" : "") : null,
                Cpu = cpu.GetValueOrDefault("Name"), Ram = long.TryParse(cs.GetValueOrDefault("TotalPhysicalMemory"), out var r) ? r : null,
                User = cs.GetValueOrDefault("UserName"), Bios = bios.GetValueOrDefault("SMBIOSBIOSVersion"),
            }.ToInfo("WMI");
        }
        catch (WinReadException) { throw; }
        catch (Exception ex) { throw Classify(ex, "WMI"); }
    }

    private static WinReadException Classify(Exception ex, string what)
    {
        if (ex is WinReadException w) return w;
        var hr = ex switch { COMException ce => ce.ErrorCode, ManagementException me => (int)me.ErrorCode, _ => ex.HResult };
        var code = $" (0x{hr:X8})";
        return (uint)hr switch
        {
            0x80070005 or 0x80041003 => new(WinFail.AccessDenied, $"{what}: access denied" + code, ex),
            0x8007052E or 0x80070056 => new(WinFail.BadLogin, $"{what}: wrong user name or password" + code, ex),
            0x80070532 => new(WinFail.BadLogin, $"{what}: the password has expired" + code, ex),
            0x80070533 => new(WinFail.BadLogin, $"{what}: the account is disabled" + code, ex),
            0x80070775 => new(WinFail.BadLogin, $"{what}: the account is locked out" + code, ex),
            0x800706BA or 0x800706BE or 0x800706BF or 0x800706D9 or 0x80070776 or 0x8007071A =>
                new(WinFail.Blocked, $"{what} is blocked by the PC's firewall (the RPC server is unavailable)" + code, ex),
            0x80070721 or 0x80090322 or 0x80090302 or 0x800706D3 =>
                new(WinFail.AccessDenied, $"{what}: Windows security refused the login ({ex.Message.Trim()})" + code, ex),
            _ => new(WinFail.Other, $"{what}: {ex.Message.Trim()}" + code, ex),
        };
    }

    // ───────────────────────────── Remote Registry (SMB) ─────────────────────────────

    /// <summary>
    /// Reads the PC over SMB (TCP 445): the Remote Registry gives maker, model, CPU and Windows version, and the copy of the
    /// firmware tables Windows keeps in the registry gives the serial number and RAM. When the Remote Registry service is off
    /// (the default on Windows 10/11) and <paramref name="mayStartService"/> is set, it is started for the read and then put
    /// back exactly as it was (stopped, and disabled again if it was disabled).
    /// </summary>
    private static (PcInfo, string?) Registry(string host, string? user, string? password, bool mayStartService)
    {
        var connected = false;
        if (user != null)
        {
            var err = Smb.Connect(host, "IPC$", user, password);
            if (Smb.IsBadLogin(err)) throw new WinReadException(WinFail.BadLogin, $"wrong user name or password ({Smb.Text(err)})");
            if (Smb.AccountProblem(err) is { } why) throw new WinReadException(WinFail.BadLogin, why);
            if (err == 5) throw new WinReadException(WinFail.AccessDenied, $"access denied ({Smb.Text(err)})");
            if (err is 53 or 1231 or 64 or 1203 or 121) throw new WinReadException(WinFail.Blocked, $"SMB does not answer ({Smb.Text(err)})");
            connected = err == 0; // 1219 = already connected with another login: use that connection
        }
        Action? putBack = null;
        string? note = null;
        try
        {
            RegistryKey? hklm = null;
            Exception? first = null;
            try { hklm = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, host, RegistryView.Registry64); }
            catch (UnauthorizedAccessException ex) { throw new WinReadException(WinFail.AccessDenied, "access to its registry denied (not an administrator there?)", ex); }
            catch (Exception ex) when (ex is IOException or Win32Exception) { first = ex; }

            if (hklm == null)
            {
                if (!mayStartService) throw new WinReadException(WinFail.Blocked, "the Remote Registry service is off on that PC", first);
                putBack = Scm.EnsureRunning(host, "RemoteRegistry", TimeSpan.FromSeconds(15), out var how);
                note = how;
                for (var attempt = 0; hklm == null; attempt++)
                {
                    try { hklm = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, host, RegistryView.Registry64); }
                    catch (UnauthorizedAccessException ex) { throw new WinReadException(WinFail.AccessDenied, "access to its registry denied", ex); }
                    catch (Exception ex) when (ex is IOException or Win32Exception)
                    {
                        if (attempt >= 4) throw new WinReadException(WinFail.Blocked, $"the Remote Registry does not answer ({ex.Message.Trim()})", ex);
                        Thread.Sleep(1000);
                    }
                }
            }
            using (hklm)
            {
                object? Raw(string path, string name)
                {
                    try { using var k = hklm.OpenSubKey(path); return k?.GetValue(name); }
                    catch (System.Security.SecurityException) { return null; }
                    catch (UnauthorizedAccessException) { return null; }
                    catch (IOException) { return null; }
                }
                string? V(string path, string name) => Raw(path, name) switch
                {
                    string[] many => many.Select(x => x.Trim()).FirstOrDefault(x => x.Length > 0),
                    byte[] => null,
                    { } one when one.ToString()!.Trim() is { Length: > 0 } v => v,
                    _ => null,
                };
                const string Bios = @"HARDWARE\DESCRIPTION\System\BIOS", Cv = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
                var product = V(Cv, "ProductName");
                var build = V(Cv, "CurrentBuild") ?? V(Cv, "CurrentBuildNumber");
                if (product != null && int.TryParse(build, out var b) && b >= 22000) product = product.Replace("Windows 10", "Windows 11");
                var fw = Raw(@"SYSTEM\CurrentControlSet\Services\mssmbios\Data", "SMBiosData") is byte[] blob ? Core.Net.Smbios.Parse(blob) : null;
                var raw = new RawPc
                {
                    Maker = V(Bios, "SystemManufacturer") ?? fw?.Manufacturer,
                    Model = V(Bios, "SystemProductName") ?? fw?.Product,
                    ProductVersion = V(Bios, "SystemVersion") ?? fw?.Version,
                    BoardMaker = V(Bios, "BaseBoardManufacturer") ?? fw?.BoardMaker, BoardProduct = V(Bios, "BaseBoardProduct") ?? fw?.BoardProduct,
                    Serial = Clean(fw?.Serial) ?? Clean(fw?.ChassisSerial),
                    Name = V(@"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", "ComputerName"),
                    Domain = V(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Domain"),
                    Windows = product == null ? null : product + (V(Cv, "DisplayVersion") is { } dv ? " " + dv : "") + (build != null ? $" (10.0.{build})" : ""),
                    Cpu = V(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString"),
                    Ram = fw?.RamBytes is > 0 ? fw.RamBytes : null,
                    Bios = V(Bios, "BIOSVersion") ?? fw?.BiosVersion,
                };
                var view = new RemoteRegView(hklm);
                try { raw.Disks = WinHardware.Join(WinHardware.Disks(view)); } catch { }
                try { raw.Graphics = WinHardware.JoinGpus(WinHardware.Gpus(view)); } catch { }
                raw.Drives = WinHardware.DrivesOverSmb(host, view);
                if (raw.Maker == null && raw.Model == null && raw.Windows == null)
                    throw new WinReadException(WinFail.AccessDenied, "the registry answered but could not be read");
                return (raw.ToInfo("Remote Registry"), note);
            }
        }
        finally
        {
            if (putBack != null) { try { putBack(); } catch { } }
            if (connected) Smb.Disconnect(host, "IPC$");
        }
    }

    // ───────────────────────────── helpers ─────────────────────────────

    /// <summary>
    /// Runs a blocking Windows call on its own thread and gives up after <paramref name="timeout"/>
    /// (a DCOM connect to a firewalled port can hang for minutes and cannot be cancelled).
    /// </summary>
    internal static async Task<T> WithTimeout<T>(Func<T> work, TimeSpan timeout, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        var t = new Thread(() =>
        {
            try { tcs.TrySetResult(work()); }
            catch (Exception ex) { tcs.TrySetException(ex); }
        }) { IsBackground = true, Name = "NetFinder Windows read" };
        t.Start();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var done = await Task.WhenAny(tcs.Task, Task.Delay(timeout, cts.Token));
        cts.Cancel();
        ct.ThrowIfCancellationRequested();
        if (done != tcs.Task)
            throw new WinReadException(WinFail.Blocked, $"no answer within {timeout.TotalSeconds:0} s (its firewall drops the connection)");
        return await tcs.Task;
    }

    /// <summary>Drops the placeholders OEMs leave in the firmware.</summary>
    internal static string? Clean(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return null;
        v = v.Trim();
        var junk = new[] { "To be filled by O.E.M.", "To Be Filled By O.E.M.", "System manufacturer", "System Product Name", "System Version", "Default string",
            "OEM", "Not Applicable", "None", "0", "System Serial Number", "Not Specified", "INVALID", "Type1ProductConfigId", "SKU" };
        return junk.Any(j => v.Equals(j, StringComparison.OrdinalIgnoreCase)) ? null : v;
    }

    /// <summary>The raw values, turned into a readable model the same way for WMI and the registry.</summary>
    private sealed class RawPc
    {
        public string? Maker, Model, ProductVersion, BoardMaker, BoardProduct, Serial, Name, Domain, Windows, Cpu, User, Bios, Disks, Drives, Graphics;
        public long? Ram;

        public PcInfo ToInfo(string via)
        {
            var maker = Clean(Maker);
            var model = Clean(Model);
            // Lenovo keeps the marketing name ("ThinkPad T14 Gen 2") in the product version, the model has the machine type
            if (maker?.Contains("lenovo", StringComparison.OrdinalIgnoreCase) == true && Clean(ProductVersion) is { } lv && !lv.Equals(model, StringComparison.OrdinalIgnoreCase))
                model = model == null ? lv : $"{lv} ({model})";
            // Self-built PC: name the motherboard instead
            if (maker == null || model == null)
            {
                var bm = Clean(BoardMaker);
                var bp = Clean(BoardProduct);
                if (bp != null) { model = $"Custom PC ({bm} {bp})".Replace("( ", "(").Trim(); maker ??= bm; }
            }
            // "OptiPlex 7090" → "Dell OptiPlex 7090" (HP and Lenovo already carry the brand)
            var brand = maker?.Split(' ', ',')[0];
            if (brand is { Length: > 1 } && model != null && !model.StartsWith("Custom PC") && !model.Contains(brand, StringComparison.OrdinalIgnoreCase))
                model = (brand.All(char.IsUpper) && brand.Length > 3 ? brand[0] + brand[1..].ToLowerInvariant() : brand) + " " + model;
            return new PcInfo(maker, model, Serial, Name, Domain, Windows, Cpu is { } c ? Regex.Replace(c, @"\s+", " ").Trim() : null, Ram, User, Bios, via, Disks, Drives, Graphics);
        }
    }
}

/// <summary>SMB connections (\\pc\IPC$, \\pc\ADMIN$) with an explicit login, through Windows itself (mpr.dll).</summary>
internal static class Smb
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NETRESOURCE
    {
        public int dwScope, dwType, dwDisplayType, dwUsage;
        public string? lpLocalName, lpRemoteName, lpComment, lpProvider;
    }

    [DllImport("mpr.dll", CharSet = CharSet.Unicode, EntryPoint = "WNetAddConnection2W")]
    private static extern int WNetAddConnection2(ref NETRESOURCE res, string? password, string? user, int flags);

    [DllImport("mpr.dll", CharSet = CharSet.Unicode, EntryPoint = "WNetCancelConnection2W")]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);

    /// <summary>0 = connected. Otherwise a Windows error code (1326 = wrong user/password, 5 = access denied…).</summary>
    public static int Connect(string host, string share, string? user, string? password)
    {
        var r = new NETRESOURCE { dwType = 0 /* RESOURCETYPE_ANY */, lpRemoteName = $@"\\{host}\{share}" };
        return WNetAddConnection2(ref r, password, user, 0);
    }

    public static void Disconnect(string host, string share)
    {
        try { WNetCancelConnection2($@"\\{host}\{share}", 0, true); } catch { }
    }

    public static bool IsBadLogin(int err) => err is 86 or 1326 or 2202;

    public static string? AccountProblem(int err) => err switch
    {
        1909 => "the account is locked out",
        1331 => "the account is disabled",
        1330 => "the password has expired",
        1907 => "the password must be changed first",
        1327 or 1328 or 1329 or 1385 => "the account may not log on over the network (account restrictions)",
        _ => null,
    };

    public static string Text(int err) => $"{new Win32Exception(err).Message.Trim().TrimEnd('.')} ({err})";
}

/// <summary>Starts a service on another PC through its Service Control Manager (over SMB) and puts it back afterwards.</summary>
internal static class Scm
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001, ServiceChangeConfig = 0x0002, ServiceQueryStatus = 0x0004, ServiceStart = 0x0010, ServiceStop = 0x0020;
    private const uint NoChange = 0xFFFFFFFF, DemandStart = 3, Disabled = 4;
    private const uint Stopped = 1, Running = 4, ControlStop = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenSCManagerW")]
    private static extern IntPtr OpenSCManager(string machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenServiceW")]
    private static extern IntPtr OpenService(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatus(IntPtr h, out SERVICE_STATUS status);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "QueryServiceConfigW")]
    private static extern bool QueryServiceConfig(IntPtr h, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "ChangeServiceConfigW")]
    private static extern bool ChangeServiceConfig(IntPtr h, uint type, uint startType, uint errorControl, string? path, string? group,
        IntPtr tagId, string? dependencies, string? user, string? password, string? displayName);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "StartServiceW")]
    private static extern bool StartService(IntPtr h, int argc, IntPtr argv);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ControlService(IntPtr h, uint control, out SERVICE_STATUS status);

    /// <summary>
    /// Makes sure <paramref name="service"/> runs on <paramref name="host"/>. Returns null when it already ran,
    /// otherwise an action that stops it again and restores its start type.
    /// </summary>
    public static Action? EnsureRunning(string host, string service, TimeSpan wait, out string? note)
    {
        note = null;
        var scm = OpenSCManager($@"\\{host}", null, ScManagerConnect);
        if (scm == IntPtr.Zero) throw Fail("open its Service Control Manager", Marshal.GetLastWin32Error());
        var svc = OpenService(scm, service, ServiceQueryConfig | ServiceChangeConfig | ServiceQueryStatus | ServiceStart | ServiceStop);
        if (svc == IntPtr.Zero)
        {
            var e = Marshal.GetLastWin32Error();
            CloseServiceHandle(scm);
            throw Fail($"open the {service} service", e);
        }
        void Close() { CloseServiceHandle(svc); CloseServiceHandle(scm); }
        try
        {
            if (QueryServiceStatus(svc, out var st) && st.dwCurrentState == Running) { Close(); return null; }
            var startType = StartType(svc);
            var enabled = false;
            if (startType == Disabled)
            {
                if (!ChangeServiceConfig(svc, NoChange, DemandStart, NoChange, null, null, IntPtr.Zero, null, null, null, null))
                    throw Fail($"enable the {service} service", Marshal.GetLastWin32Error());
                enabled = true;
            }
            void PutBack()
            {
                try
                {
                    ControlService(svc, ControlStop, out _);
                    if (enabled) ChangeServiceConfig(svc, NoChange, Disabled, NoChange, null, null, IntPtr.Zero, null, null, null, null);
                }
                finally { Close(); }
            }
            if (!StartService(svc, 0, IntPtr.Zero))
            {
                var e = Marshal.GetLastWin32Error();
                if (e != 1056 /* already running */) { PutBack(); throw Fail($"start the {service} service", e); }
            }
            var until = DateTime.UtcNow + wait;
            while (DateTime.UtcNow < until && (!QueryServiceStatus(svc, out st) || st.dwCurrentState != Running))
            {
                if (st.dwCurrentState == Stopped && st.dwWin32ExitCode != 0) break;
                Thread.Sleep(300);
            }
            note = enabled ? $"{service} was disabled: enabled and started it for the read, then stopped and disabled it again"
                           : $"{service} was stopped: started it for the read, then stopped it again";
            return PutBack;
        }
        catch { Close(); throw; }
    }

    private static uint StartType(IntPtr svc)
    {
        QueryServiceConfig(svc, IntPtr.Zero, 0, out var needed);
        if (needed <= 0) return NoChange;
        var buf = Marshal.AllocHGlobal(needed);
        try { return QueryServiceConfig(svc, buf, needed, out _) ? (uint)Marshal.ReadInt32(buf, 4) : NoChange; }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static WinReadException Fail(string what, int err) => err == 5
        ? new WinReadException(WinFail.NotAdmin, $"could not {what}: access denied (not an administrator on that PC?)")
        : new WinReadException(err is 53 or 1722 or 1753 ? WinFail.Blocked : WinFail.Other, $"could not {what} ({Smb.Text(err)})");
}
