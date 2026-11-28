using System.ComponentModel;
using System.Diagnostics;

namespace NetFinder.Core.Actions;

public static class Launcher
{
    /// <summary>Open a URL / file / UNC path with the default Windows handler (web links: in the user's own browser, see <see cref="OpenInUserBrowser"/>).</summary>
    public static void Open(string target)
    {
        if (IsWebLink(target) && OpenInUserBrowser(target)) return;
        OpenElevated(target);
    }

    /// <summary>The plain way: the program opened runs as administrator, like NetFinder.</summary>
    public static void OpenElevated(string target) => Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });

    public static bool IsWebLink(string t) => t.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || t.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// NetFinder runs as administrator, so a browser it starts runs as administrator too. When the user's Chrome is
    /// already open (not as administrator) the two can't talk, and Chrome shows an empty window instead of the page.
    /// Explorer never runs as administrator: started from here it hands the link to the desktop's own Explorer, which
    /// opens it in the user's normal browser (a new tab in the Chrome that is already open). False when it could not.
    /// </summary>
    public static bool OpenInUserBrowser(string url)
    {
        if (!OperatingSystem.IsWindows() || url.Contains('"')) return false;
        try
        {
            if (Process.GetProcessesByName("explorer").Length == 0) return false; // no desktop shell to hand it to
            var explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
            using var p = Process.Start(new ProcessStartInfo(explorer, "\"" + url + "\"") { UseShellExecute = false });
            return p != null;
        }
        catch { return false; }
    }

    /// <summary>Open a link whose handler may not be installed (vnc://, rtsp://…); explains what to install if not.</summary>
    public static void OpenWithHint(string target, string missingHint)
    {
        try { Open(target); }
        catch (Win32Exception ex) { throw new InvalidOperationException(missingHint + "\n\n(" + ex.Message + ")", ex); }
    }

    /// <summary>Run a program in a new visible console window (ping -t, ssh, telnet...).</summary>
    public static void Console(string commandLine) =>
        Process.Start(new ProcessStartInfo("cmd.exe", "/k " + commandLine) { UseShellExecute = true });

    public static void Run(string exe, string args) => Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = true });

    /// <summary>SSH: PuTTY if installed (handles old switches best), else Windows' own ssh.exe asking for the login name.</summary>
    public static void Ssh(string ip, int port = 22)
    {
        if (FindTool("putty.exe", "PuTTY") is { } putty) { Run(putty, $"-ssh {ip} -P {port}"); return; }
        var ssh = Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh.exe");
        if (File.Exists(ssh) || FindOnPath("ssh.exe") != null)
        {
            // /v:on = delayed expansion, so !U! is read after "set /p" asked for it
            Run("cmd.exe", $"/v:on /k \"title SSH {ip} & set /p U=Login as: & ssh -p {port} !U!@{ip}\"");
            return;
        }
        throw new InvalidOperationException("No SSH program found on this PC.\n\nInstall PuTTY (putty.org), or turn on Windows' \"OpenSSH Client\" " +
                                            "(Settings → Apps → Optional features → Add a feature → OpenSSH Client).");
    }

    /// <summary>Telnet: Windows' telnet.exe if it is turned on, else PuTTY.</summary>
    public static void Telnet(string ip, int port = 23)
    {
        if (File.Exists(Path.Combine(Environment.SystemDirectory, "telnet.exe")) || FindOnPath("telnet.exe") != null)
        {
            Console($"title Telnet {ip} & telnet {ip} {port}");
            return;
        }
        if (FindTool("putty.exe", "PuTTY") is { } putty) { Run(putty, $"-telnet {ip} -P {port}"); return; }
        throw new InvalidOperationException("Windows' Telnet client is turned off on this PC.\n\nTurn it on once: Start → \"Turn Windows features on or off\" → tick \"Telnet Client\" → OK.\n" +
                                            "Or install PuTTY (putty.org); it does Telnet and SSH.");
    }

    public const string WinboxDownload = "https://mikrotik.com/download";

    /// <summary>MikroTik Winbox: winbox64.exe / winbox.exe next to NetFinder, in Downloads, on the Desktop or in Program Files.</summary>
    public static void Winbox(string ip)
    {
        var exe = FindTool("winbox64.exe", "Winbox", "MikroTik") ?? FindTool("winbox.exe", "Winbox", "MikroTik");
        if (exe != null) { Run(exe, ip); return; }
        Open(WinboxDownload);
        throw new InvalidOperationException("Winbox is not on this PC, so the MikroTik download page was opened.\n\n" +
                                            "Download winbox64.exe and put it in your Downloads folder or next to NetFinder.exe; the button will find it next time.\n" +
                                            $"(Meanwhile you can open the router's web page: http://{ip})");
    }

    /// <summary>VNC: a vnc:// handler, or a known VNC viewer.</summary>
    public static void Vnc(string ip)
    {
        var viewer = FindTool("vncviewer.exe", "RealVNC", "VNC Viewer", "TightVNC", "uvnc bvba\\UltraVNC", "UltraVNC", "TigerVNC")
                     ?? FindTool("tvnviewer.exe", "TightVNC");
        if (viewer != null) { Run(viewer, ip); return; }
        OpenWithHint($"vnc://{ip}", "No VNC viewer is installed. Install RealVNC Viewer, TightVNC or UltraVNC, then try again.");
    }

    /// <summary>Looks for a program next to NetFinder, in Downloads/Desktop, on PATH and in Program Files\&lt;folders&gt;.</summary>
    public static string? FindTool(string exeName, params string[] programFolders)
    {
        var dirs = new List<string>();
        void Add(string? d) { if (!string.IsNullOrEmpty(d)) dirs.Add(d); }
        Add(AppContext.BaseDirectory);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        Add(Path.Combine(profile, "Downloads"));
        Add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
        foreach (var root in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) }.Distinct())
            foreach (var f in programFolders)
                if (!string.IsNullOrEmpty(root)) Add(Path.Combine(root, f));
        foreach (var d in dirs)
        {
            try
            {
                var p = Path.Combine(d, exeName);
                if (File.Exists(p)) return p;
            }
            catch { }
        }
        return FindOnPath(exeName);
    }

    private static string? FindOnPath(string exeName)
    {
        foreach (var d in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var p = Path.Combine(d.Trim('"'), exeName);
                if (File.Exists(p)) return p;
            }
            catch { }
        }
        return null;
    }
}
