namespace NetFinder.Core.Net;

public enum PortRiskLevel { None, Note, High }

/// <summary>One open port worth a word: what it is, how risky, and what to do about it.</summary>
public sealed record PortFinding(int Port, string Service, PortRiskLevel Level, string Advice);

/// <summary>
/// Names the services behind open TCP ports and flags the risky ones (passwords sent as plain text,
/// services that are often left without a password, old protocols that have been attacked a lot).
/// </summary>
public static class PortRisk
{
    /// <summary>Ports added to the check in 1.1.15 so the risky services are seen too.</summary>
    public static readonly int[] ExtraPorts = { 512, 513, 514, 1433, 1723, 2375, 5800, 5985, 6379, 9200, 11211, 27017 };

    /// <summary>The services people ask about first; the device pane shows each as open or closed.</summary>
    public static readonly (int Port, string Name)[] KeyServices =
    {
        (3389, "Remote Desktop"), (445, "File sharing (SMB)"), (80, "Web (HTTP)"), (443, "Web (HTTPS)"),
        (22, "SSH"), (23, "Telnet"), (21, "FTP"), (5900, "VNC"),
    };

    public static string Service(int p) => p switch
    {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP", 53 => "DNS", 80 => "HTTP", 81 or 82 or 88 => "HTTP", 110 => "POP3", 135 => "Windows RPC",
        139 => "NetBIOS", 143 => "IMAP", 161 => "SNMP", 443 => "HTTPS", 445 => "SMB (file sharing)", 502 => "Modbus", 512 => "rexec", 513 => "rlogin",
        514 => "rsh", 515 => "LPD printer", 554 => "RTSP (video)", 631 => "IPP printer", 1433 => "SQL Server", 1723 => "PPTP VPN", 1883 => "MQTT",
        1900 => "UPnP", 2375 => "Docker API", 3000 => "Web", 3306 => "MySQL", 3389 => "Remote Desktop", 5000 or 5001 => "Web / NAS", 5060 => "SIP",
        5432 => "PostgreSQL", 5800 => "VNC (web)", 5900 => "VNC", 5985 => "WinRM", 6379 => "Redis", 7547 => "TR-069", 8000 or 8001 => "Web",
        8008 or 8009 => "Cast", 8080 or 8081 or 8088 or 8888 or 8899 => "HTTP alt", 8291 => "Winbox", 8443 => "HTTPS alt", 8728 => "MikroTik API",
        9000 => "Web", 9100 => "Printer (RAW)", 9200 => "Elasticsearch", 11211 => "Memcached", 27017 => "MongoDB", 37777 => "Dahua",
        49152 => "UPnP", 62078 => "Apple sync",
        _ => "",
    };

    /// <summary>What is worth knowing about these open ports, risky ones first.</summary>
    public static List<PortFinding> Check(IReadOnlyCollection<int> open)
    {
        var list = new List<PortFinding>();
        void Add(PortRiskLevel level, int port, string advice, string? name = null)
        {
            if (open.Contains(port)) list.Add(new PortFinding(port, name ?? Service(port), level, advice));
        }
        const PortRiskLevel high = PortRiskLevel.High, note = PortRiskLevel.Note;

        Add(high, 23, "Sends the password as plain text. Turn Telnet off and use SSH.");
        Add(high, 21, "Sends the password as plain text. Use SFTP, or turn FTP off.");
        foreach (var p in new[] { 512, 513, 514 }) Add(high, p, "Old remote login with no encryption. Turn it off.");
        if (open.Contains(5900)) Add(high, 5900, "Controls the screen remotely and often has a weak password or none. Set a strong password or turn it off.");
        else Add(high, 5800, "Controls the screen remotely and often has a weak password or none. Set a strong password or turn it off.");
        Add(high, 2375, "Docker control with no password: anyone on the network can take over this machine.");
        Add(high, 6379, "Often left with no password. Allow only the servers that need it.");
        Add(high, 27017, "Often left with no password. Allow only the servers that need it.");
        Add(high, 9200, "Often left with no password. Allow only the servers that need it.");
        Add(high, 11211, "Has no password. Allow only the servers that need it.");
        Add(high, 7547, "Remote management by the internet provider; it has been attacked many times. Turn it off if nobody uses it.");
        Add(high, 502, "Industrial control with no password: anyone on the network can read or change this device.");
        Add(high, 1723, "Old VPN with weak encryption. Use another VPN type.");

        Add(note, 3389, "Fine inside the office. Never open it to the internet, and keep Windows updated.");
        Add(note, 445, "Keep Windows updated and SMBv1 turned off.");
        foreach (var p in new[] { 1433, 3306, 5432 }) Add(note, p, "A database open to the whole network. Allow only the computers that need it.");
        Add(note, 5985, "Windows remote management. Fine for admins; keep it closed on normal PCs.");
        Add(note, 8291, "MikroTik admin. Keep RouterOS updated and use a strong password.");
        Add(note, 8728, "MikroTik API. Turn it off if you don't use it.");
        Add(note, 1883, "Messages of smart devices. Make sure it needs a password.");
        if (!open.Contains(443) && !open.Contains(8443))
            Add(note, 80, "Web page without encryption: the login password is sent as plain text.");
        return list.OrderByDescending(f => f.Level).ThenBy(f => f.Port).ToList();
    }

    public static List<PortFinding> Risky(IReadOnlyCollection<int> open) => Check(open).Where(f => f.Level == PortRiskLevel.High).ToList();

    /// <summary>"23 Telnet, 21 FTP" (only the risky ones), for the list and the exports.</summary>
    public static string RiskyText(IReadOnlyCollection<int> open) => string.Join(", ", Risky(open).Select(f => $"{f.Port} {f.Service}"));
}
