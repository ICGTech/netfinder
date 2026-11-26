using System.Diagnostics;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace NetFinder.Core.Update;

/// <summary>
/// Gets the official Npcap installer and runs it.
/// Npcap's free license does not allow shipping it inside our program, so it is fetched from the
/// official sites (npcap.com, then nmap.org which is run by the same people), or the user picks
/// an installer file they downloaded elsewhere.
/// </summary>
public static class NpcapInstaller
{
    public const string DownloadPage = "https://npcap.com/#download";

    /// <summary>Pages that list the current installer, tried in order.</summary>
    private static readonly (string Page, string DistBase)[] Sources =
    {
        ("https://npcap.com/", "https://npcap.com/dist/"),
        ("https://nmap.org/npcap/", "https://nmap.org/npcap/dist/"),
    };

    /// <summary>Thrown when none of the official sites can be reached (no internet, DNS or firewall block).</summary>
    public sealed class UnreachableException : Exception
    {
        public UnreachableException(string message, Exception? inner) : base(message, inner) { }
    }

    public static async Task<string> DownloadAsync(IProgress<int>? progress, CancellationToken ct)
    {
        var errors = new List<string>();
        Exception? last = null;
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        foreach (var (page, dist) in Sources)
        {
            try
            {
                using var pageCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                pageCts.CancelAfter(TimeSpan.FromSeconds(20));
                var html = await http.GetStringAsync(page, pageCts.Token);
                var m = Regex.Match(html, @"npcap-(\d+\.\d+)\.exe");
                if (!m.Success) { errors.Add($"{page}: no installer link"); continue; }
                var url = dist + "npcap-" + m.Groups[1].Value + ".exe";
                var file = Path.Combine(Path.GetTempPath(), Path.GetFileName(url));
                using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
                resp.EnsureSuccessStatusCode();
                var total = resp.Content.Headers.ContentLength ?? 0;
                await using (var src = await resp.Content.ReadAsStreamAsync(ct))
                await using (var dst = File.Create(file))
                {
                    var buf = new byte[81920]; long got = 0; int r;
                    while ((r = await src.ReadAsync(buf, ct)) > 0)
                    {
                        await dst.WriteAsync(buf.AsMemory(0, r), ct);
                        got += r;
                        if (total > 0) progress?.Report((int)Math.Min(99, got * 100 / total));
                    }
                }
                return file;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                last = ex;
                errors.Add($"{new Uri(page).Host}: {ex.Message}");
            }
        }
        throw new UnreachableException(string.Join("\n", errors), last);
    }

    /// <summary>Runs an Npcap installer and waits until the user closes it. Returns its exit code.</summary>
    public static async Task<int> RunInstallerAsync(string installer, CancellationToken ct)
    {
        if (!Path.GetFileName(installer).StartsWith("npcap", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("That file does not look like an Npcap installer (npcap-x.yy.exe).");
        try { File.Delete(installer + ":Zone.Identifier"); } catch { }
        // /winpcap_mode=yes keeps the WinPcap-compatible API that the capture library uses
        using var p = Process.Start(new ProcessStartInfo(installer, "/winpcap_mode=yes") { UseShellExecute = true })!;
        await p.WaitForExitAsync(ct);
        return p.ExitCode;
    }

    /// <summary>An Npcap installer the user already downloaded (Downloads folder, next to our .exe), newest first.</summary>
    public static string? FindLocalInstaller()
    {
        var dirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.GetDirectoryName(Environment.ProcessPath ?? "") ?? "",
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };
        return dirs.Where(Directory.Exists)
            .SelectMany(d => { try { return Directory.GetFiles(d, "npcap-*.exe"); } catch { return Array.Empty<string>(); } })
            .OrderByDescending(File.GetLastWriteTime)
            .FirstOrDefault();
    }
}
