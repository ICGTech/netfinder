using System.Diagnostics;
using System.Text.RegularExpressions;

namespace NetFinder.Core.Update;

/// <summary>
/// Downloads the official Npcap installer from npcap.com and runs it.
/// (Npcap's free license does not allow shipping it inside our program, so we fetch it from the source.)
/// </summary>
public static class NpcapInstaller
{
    public const string DownloadPage = "https://npcap.com/#download";

    public static async Task<string> FindLatestUrlAsync(CancellationToken ct)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        var html = await http.GetStringAsync("https://npcap.com/", ct);
        var m = Regex.Match(html, @"(https://npcap\.com/)?dist/npcap-(\d+\.\d+)\.exe");
        if (!m.Success) throw new InvalidOperationException("Could not find the Npcap download link.");
        return "https://npcap.com/dist/npcap-" + m.Groups[2].Value + ".exe";
    }

    /// <summary>Downloads and starts the installer, then waits until the user finishes it. Returns the installer exit code.</summary>
    public static async Task<int> DownloadAndRunAsync(IProgress<int>? progress, CancellationToken ct)
    {
        var url = await FindLatestUrlAsync(ct);
        var file = Path.Combine(Path.GetTempPath(), Path.GetFileName(url));
        using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) })
        using (var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct))
        {
            resp.EnsureSuccessStatusCode();
            var total = resp.Content.Headers.ContentLength ?? 0;
            await using var src = await resp.Content.ReadAsStreamAsync(ct);
            await using var dst = File.Create(file);
            var buf = new byte[81920]; long got = 0; int r;
            while ((r = await src.ReadAsync(buf, ct)) > 0)
            {
                await dst.WriteAsync(buf.AsMemory(0, r), ct);
                got += r;
                if (total > 0) progress?.Report((int)(got * 100 / total));
            }
        }
        // /winpcap_mode=yes keeps the WinPcap-compatible API that the capture library uses
        using var p = Process.Start(new ProcessStartInfo(file, "/winpcap_mode=yes") { UseShellExecute = true })!;
        await p.WaitForExitAsync(ct);
        return p.ExitCode;
    }
}
