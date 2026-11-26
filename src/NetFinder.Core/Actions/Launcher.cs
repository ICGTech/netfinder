using System.Diagnostics;

namespace NetFinder.Core.Actions;

public static class Launcher
{
    /// <summary>Open a URL / file / UNC path with the default Windows handler.</summary>
    public static void Open(string target) => Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });

    /// <summary>Run a program in a new visible console window (ping -t, ssh, telnet...).</summary>
    public static void Console(string commandLine) =>
        Process.Start(new ProcessStartInfo("cmd.exe", "/k " + commandLine) { UseShellExecute = true });

    public static void Run(string exe, string args) => Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = true });
}
