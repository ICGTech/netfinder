using System.Text.RegularExpressions;
using NetFinder.Core.Model;

namespace NetFinder.Core.Classifiers;

/// <summary>
/// Signs that a Windows machine is a server and not a PC: a Windows Server edition, a domain controller
/// (Kerberos 88, LDAP 389 / 636 / 3268, the NetBIOS domain controller name), a DNS server, server hardware,
/// or two server roles together (SQL Server, WinRM, Hyper-V). Works on any network: nothing here is about one site.
/// </summary>
public static class ServerSigns
{
    /// <summary>LDAP, LDAP over TLS, global catalog (+TLS): only domain controllers listen on these.</summary>
    public static readonly int[] DirectoryPorts = { 389, 636, 3268, 3269 };
    private static readonly Regex ServerEdition = new(@"\bServer\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ServerHardware = new(@"poweredge|proliant|thinksystem|thinkserver|primergy|system x\d|\bx3[0-9]{3}\b|supermicro super server", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Not a Linux / network device by its TTL (64 or 255). Unknown TTL counts as possible.</summary>
    private static bool TtlAllowsWindows(Device d) => d.Info.GetValueOrDefault("TTL") is not ("64" or "255");

    /// <summary>The Windows edition was read: true for "Windows Server 2019 Standard", false for "Windows 11 Pro", null when not read.</summary>
    public static bool? EditionIsServer(Device d) =>
        d.Info.TryGetValue("Windows", out var w) && !string.IsNullOrWhiteSpace(w) ? ServerEdition.IsMatch(w) : null;

    /// <summary>
    /// Looks like Windows: the edition was read, or Windows RPC (135) / Remote Desktop (3389) answers and the TTL is not a
    /// Linux one, or file sharing answers with Windows' TTL. File sharing alone is not enough: routers and NAS boxes share files too.
    /// </summary>
    public static bool LooksWindows(Device d) =>
        d.Info.ContainsKey("Windows") ||
        ((d.OpenPorts.Contains(135) || d.OpenPorts.Contains(3389)) && TtlAllowsWindows(d)) ||
        ((d.OpenPorts.Contains(445) || d.OpenPorts.Contains(139)) && d.Info.GetValueOrDefault("TTL") == "128");

    /// <summary>Port 88 of a Windows machine is Kerberos (domain logins), not a web page.</summary>
    public static bool IsKerberos(Device d) =>
        d.OpenPorts.Contains(88) && !d.PortInfo.ContainsKey(88) && (LooksWindows(d) || DirectoryPorts.Any(d.OpenPorts.Contains));

    /// <summary>Why this machine looks like a Windows server; empty for a normal PC. Call inside lock(d).</summary>
    public static List<string> Reasons(Device d)
    {
        var why = new List<string>();
        var edition = EditionIsServer(d);
        if (edition == false) return why; // "Windows 11 Pro": a PC, whatever it runs
        if (edition == true) why.Add("Windows Server edition");
        var dcName = d.Info.GetValueOrDefault("Domain role");
        if (!LooksWindows(d) && dcName == null) return why;
        if (dcName != null) why.Add(dcName + " (NetBIOS)");
        if (IsKerberos(d)) why.Add("domain controller (Kerberos, port 88)");
        var ldap = DirectoryPorts.FirstOrDefault(d.OpenPorts.Contains);
        if (ldap > 0) why.Add($"domain controller (LDAP, port {ldap})");
        if (d.OpenPorts.Contains(53)) why.Add("DNS server (port 53)");
        if (ServerHardware.IsMatch(d.Model ?? "")) why.Add($"server hardware ({d.Model})");
        // a PC can run one of these, a server often runs two
        var roles = new List<string>();
        if (d.OpenPorts.Contains(1433)) roles.Add("SQL Server (port 1433)");
        if (d.OpenPorts.Contains(5985)) roles.Add("WinRM (port 5985)");
        if (d.OpenPorts.Contains(2179)) roles.Add("Hyper-V (port 2179)");
        if (roles.Count >= 2) why.AddRange(roles);
        return why;
    }
}
