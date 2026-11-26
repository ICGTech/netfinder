using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Text.Json;

namespace NetFinder.Core.Update;

public sealed record UpdateInfo(string Version, string Notes, string PageUrl, string DownloadUrl, string AssetName);

/// <summary>
/// Checks GitHub Releases of <see cref="AppInfo.UpdateRepo"/> for a newer version and installs it.
/// Publishing an update = creating a GitHub release with tag "v1.2.0" and NetFinder.exe (or a .zip with it) attached.
/// </summary>
public static class UpdateChecker
{
    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        var c = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(AppInfo.Name.Replace(' ', '-'), AppInfo.Version));
        c.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        return c;
    }

    /// <summary>Set from Settings.UpdateSource at startup; falls back to AppInfo.UpdateRepo.</summary>
    public static string Source { get; set; } = AppInfo.UpdateRepo;

    public static bool Enabled => !string.IsNullOrWhiteSpace(Source);

    /// <summary>Returns the newer release, or null when up to date / not configured / offline.</summary>
    public static async Task<UpdateInfo?> CheckAsync(CancellationToken ct = default)
    {
        if (!Enabled) return null;
        var src = Source.Trim();
        if (src.StartsWith("http", StringComparison.OrdinalIgnoreCase)) return await CheckManifestAsync(src, ct);
        using var resp = await Http.GetAsync($"https://api.github.com/repos/{src}/releases/latest", ct);
        if (!resp.IsSuccessStatusCode) return null;
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var root = doc.RootElement;
        var tag = root.GetProperty("tag_name").GetString() ?? "";
        if (!IsNewer(tag, AppInfo.Version)) return null;
        string? url = null, name = null;
        foreach (var a in root.GetProperty("assets").EnumerateArray())
        {
            var n = a.GetProperty("name").GetString() ?? "";
            var u = a.GetProperty("browser_download_url").GetString() ?? "";
            if (n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) { url = u; name = n; break; }
            if (n.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) && !n.Contains("source", StringComparison.OrdinalIgnoreCase)) { url ??= u; name ??= n; }
        }
        if (url == null || name == null) return null;
        return new UpdateInfo(tag.TrimStart('v', 'V'), root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "",
            root.GetProperty("html_url").GetString() ?? "", url, name);
    }

    /// <summary>version.json: {"version":"1.2.0","url":"https://…/NetFinder.exe","notes":"…","page":"https://…"}</summary>
    private static async Task<UpdateInfo?> CheckManifestAsync(string url, CancellationToken ct)
    {
        var json = await Http.GetStringAsync(url, ct);
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        var ver = r.GetProperty("version").GetString() ?? "";
        if (!IsNewer(ver, AppInfo.Version)) return null;
        var dl = r.GetProperty("url").GetString() ?? "";
        var name = Path.GetFileName(new Uri(dl).AbsolutePath);
        if (string.IsNullOrEmpty(name)) name = AppInfo.Name + ".exe";
        return new UpdateInfo(ver.TrimStart('v', 'V'),
            r.TryGetProperty("notes", out var n) ? n.GetString() ?? "" : "",
            r.TryGetProperty("page", out var pg) ? pg.GetString() ?? dl : dl, dl, name);
    }

    public static bool IsNewer(string tag, string current) =>
        Version.TryParse(tag.TrimStart('v', 'V'), out var a) && Version.TryParse(current, out var b) && a > b;

    /// <summary>
    /// Downloads the update and starts a small script that waits for this program to exit,
    /// replaces the .exe and starts the new version. The caller must exit right after.
    /// </summary>
    public static async Task InstallAsync(UpdateInfo info, IProgress<int>? progress, CancellationToken ct)
    {
        var dir = Path.Combine(Path.GetTempPath(), AppInfo.DataFolderName + "-update");
        if (Directory.Exists(dir)) Directory.Delete(dir, true);
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, info.AssetName);

        using (var resp = await Http.GetAsync(info.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct))
        {
            resp.EnsureSuccessStatusCode();
            var total = resp.Content.Headers.ContentLength ?? 0;
            await using var src = await resp.Content.ReadAsStreamAsync(ct);
            await using var dst = File.Create(file);
            var buf = new byte[81920];
            long got = 0; int r;
            while ((r = await src.ReadAsync(buf, ct)) > 0)
            {
                await dst.WriteAsync(buf.AsMemory(0, r), ct);
                got += r;
                if (total > 0) progress?.Report((int)(got * 100 / total));
            }
        }

        var newExe = file;
        if (file.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            var unz = Path.Combine(dir, "unzipped");
            ZipFile.ExtractToDirectory(file, unz);
            newExe = Directory.GetFiles(unz, "*.exe", SearchOption.AllDirectories).FirstOrDefault()
                     ?? throw new InvalidOperationException("The update package has no .exe inside.");
        }

        var current = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot find the running program.");
        var pid = Environment.ProcessId;
        var script = Path.Combine(dir, "update.cmd");
        File.WriteAllText(script,
            "@echo off\r\n" +
            ":wait\r\n" +
            $"tasklist /FI \"PID eq {pid}\" 2>nul | find \"{pid}\" >nul && (timeout /t 1 /nobreak >nul & goto wait)\r\n" +
            "set n=0\r\n" +
            ":copy\r\n" +
            $"copy /y \"{newExe}\" \"{current}\" >nul 2>&1 || (set /a n+=1 & timeout /t 1 /nobreak >nul & if %n% lss 15 goto copy)\r\n" +
            $"start \"\" \"{current}\"\r\n");
        Process.Start(new ProcessStartInfo("cmd.exe", $"/c \"{script}\"") { CreateNoWindow = true, UseShellExecute = false, WindowStyle = ProcessWindowStyle.Hidden });
    }
}
