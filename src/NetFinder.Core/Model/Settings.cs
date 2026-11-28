using System.Text.Json;

namespace NetFinder.Core.Model;

/// <summary>User settings, saved as JSON in %AppData%\NetFinder\settings.json.</summary>
public sealed class Settings
{
    /// <summary>
    /// Subnets probed with ARP even though this PC has no address in them.
    /// These are the factory defaults of most routers, cameras, switches, printers and IoT devices.
    /// </summary>
    public List<string> ProbeSubnets { get; set; } = new()
    {
        "192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24", "192.168.4.0/24",
        "192.168.5.0/24", "192.168.8.0/24", "192.168.10.0/24", "192.168.11.0/24", "192.168.20.0/24",
        "192.168.31.0/24", "192.168.50.0/24", "192.168.88.0/24", "192.168.100.0/24", "192.168.123.0/24",
        "192.168.137.0/24", "192.168.178.0/24", "192.168.223.0/24", "192.168.254.0/24",
        "10.0.0.0/24", "10.0.1.0/24", "10.1.1.0/24", "10.10.10.0/24", "10.10.1.0/24",
        "172.16.0.0/24", "172.16.1.0/24", "172.20.10.0/24",
    };

    /// <summary>Also probe the subnets that devices reveal passively (e.g. a device asking for its gateway 192.168.5.1).</summary>
    public bool ProbeLearnedSubnets { get; set; } = true;

    /// <summary>Probe all of 169.254.x.x (65k addresses, takes ~30 s). Off by default.</summary>
    public bool ProbeLinkLocal { get; set; }

    /// <summary>Deep scan: probe every address in 192.168.0.0/16 (65k addresses, ~35 s). Toggled from the toolbar.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public bool DeepScan { get; set; }

    /// <summary>Dark colors for the main window (☰ menu → Dark mode).</summary>
    public bool DarkMode { get; set; }

    /// <summary>Largest local subnet swept fully (16 = up to 65,536 addresses). Bigger ones are swept around this PC's IP.</summary>
    public int SweepPrefixLimit { get; set; } = 16;

    /// <summary>Text of the Range box (empty = automatic: my own subnet). E.g. "10.10.20.1-254, 10.10.30.0/24".</summary>
    public string ScanRanges { get; set; } = "";

    public int ProbeRate { get; set; } = 1500;
    [System.Text.Json.Serialization.JsonIgnore]
    public int FramesPerSecond { get => ProbeRate; set => ProbeRate = value; }

    /// <summary>Check for a new version on startup and every 12 hours.</summary>
    public bool CheckForUpdates { get; set; } = true;

    /// <summary>
    /// Where to look for new versions: "owner/repo" on GitHub, or a URL to a version.json file
    /// ({"version":"1.2.0","url":"https://…/NetFinder.exe","notes":"…"}). Empty = use AppInfo.UpdateRepo.
    /// </summary>
    public string UpdateSource { get; set; } = "";
    public string? SkippedVersion { get; set; }
    /// <summary>Version that ran last time; used to show "what's new" once after an update.</summary>
    public string? LastVersion { get; set; }

    public List<int> Ports { get; set; } = new()
    {
        21, 22, 23, 25, 53, 80, 81, 82, 88, 110, 139, 143, 161, 443, 445, 502, 554, 631, 1883, 1900, 3000, 3306, 3389,
        5000, 5001, 5060, 5432, 5900, 7547, 8000, 8001, 8008, 8080, 8081, 8088, 8443, 8728, 8888, 8899, 9000, 9100, 37777, 49152, 62078, 8009, 8291, 135,
        // 1.1.15: risky services (see PortRisk)
        512, 513, 514, 1433, 1723, 2375, 5800, 5985, 6379, 9200, 11211, 27017,
    };

    /// <summary>
    /// Bumped when new ports join the default list, so a saved list gets them once. No initial value on purpose:
    /// a file from an older version has no PortsVersion, so it reads as 0 and gets the new ports.
    /// </summary>
    public int PortsVersion { get; set; }

    /// <summary>Devices pinged by "Watch devices" (kept between runs).</summary>
    public List<WatchItem> Watch { get; set; } = new();
    /// <summary>How often each watched device is pinged.</summary>
    public int WatchSeconds { get; set; } = 60;
    /// <summary>Play a sound when a watched device goes down or comes back.</summary>
    public bool WatchSound { get; set; } = true;

    public int PortTimeoutMs { get; set; } = 700;

    /// <summary>SNMP read communities tried to read model / serial (comma separated). Only "public" by default.</summary>
    public string SnmpCommunities { get; set; } = "public";
    [System.Text.Json.Serialization.JsonIgnore]
    public IReadOnlyList<string> SnmpCommunityList =>
        SnmpCommunities.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct().Take(5).ToList();
    public bool AutoCheckPorts { get; set; } = true;

    /// <summary>Prefix used for the temporary IP added to reach a device on another subnet.</summary>
    public int ReachPrefix { get; set; } = 24;

    public static string Folder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), AppInfo.DataFolderName);
    public static string FilePath => Path.Combine(Folder, "settings.json");

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static Settings Load()
    {
        try
        {
            if (File.Exists(FilePath) && JsonSerializer.Deserialize<Settings>(File.ReadAllText(FilePath)) is { } s)
            {
                // 1.1.6: port 135 tells Windows PCs apart (for "Get model" over WMI)
                if (!s.Ports.Contains(135)) s.Ports.Add(135);
                // 1.1.15: risky services. 
                if (s.PortsVersion < 2)
                {
                    foreach (var p in Net.PortRisk.ExtraPorts) if (!s.Ports.Contains(p)) s.Ports.Add(p);
                    s.PortsVersion = 2;
                }
                s.WatchSeconds = Math.Clamp(s.WatchSeconds, 10, 3600);
                return s;
            }
        }
        catch { }
        return new Settings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Folder);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, Json));
        }
        catch { }
    }
}

/// <summary>A device picked in "Watch devices". The MAC lets the IP follow the device when DHCP changes it.</summary>
public sealed class WatchItem
{
    public string Ip { get; set; } = "";
    public string Mac { get; set; } = "";
    public string Name { get; set; } = "";
}
