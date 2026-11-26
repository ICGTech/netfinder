namespace NetFinder.Core;

/// <summary>
/// Change the program name, version and branding here. Everything in the UI reads from this class.
/// (To rename the .exe file itself, change AssemblyName in src/NetFinder/NetFinder.csproj.)
/// </summary>
public static class AppInfo
{
    public const string Name = "NetFinder";

    /// <summary>Taken from &lt;Version&gt; in src/NetFinder/NetFinder.csproj (the release workflow sets it from the git tag).</summary>
    public static string Version
    {
        get
        {
            var v = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Version;
            return v == null ? "0.0.0" : $"{v.Major}.{v.Minor}.{Math.Max(0, v.Build)}";
        }
    }

    /// <summary>
    /// GitHub repository ("owner/repo") whose Releases are checked for updates.
    /// Leave empty to disable the update check.
    /// </summary>
    public const string UpdateRepo = "ICGTech/netfinder";
    /// <summary>Publisher shown in the title bar, About box and the .exe properties (also set Company in NetFinder.csproj).</summary>
    public const string Company = "ICG Technology";

    public const string Tagline = "Find any device on the wire, even on another subnet";

    /// <summary>Folder under %AppData% used for settings.</summary>
    public const string DataFolderName = "NetFinder";
}
