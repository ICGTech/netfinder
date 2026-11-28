using NetFinder.Core.Model;
using NetFinder.Core.Net;

namespace NetFinder.Core.Plugins;

// ─────────────────────────────────────────────────────────────────────────────
//  EXTENSION POINTS
//  Add a new class implementing one of these interfaces (anywhere in the solution,
//  or in a separate DLL dropped into the "plugins" folder next to the .exe) and it
//  is picked up automatically at startup. See docs/PLUGINS.md.
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>Passive: looks at every captured frame and records what it reveals.</summary>
public interface IPacketAnalyzer
{
    string Name { get; }
    void Analyze(Frame frame, CaptureContext ctx);
}

/// <summary>Active: sends probes when the user presses Scan.</summary>
public interface IActiveScanner
{
    string Name { get; }
    string Description { get; }
    /// <summary>Lower runs first.</summary>
    int Order { get; }
    /// <summary>Needs Npcap raw send/capture.</summary>
    bool RequiresCapture { get; }
    Task RunAsync(ScanContext ctx, CancellationToken ct);
}

/// <summary>Buttons shown in the device tab (Open in browser, SSH, RDP...).</summary>
public interface IDeviceActionProvider
{
    IEnumerable<DeviceAction> GetActions(Device device);
}

/// <summary>Runs after a device's ports were checked; can add info (web title, banner...).</summary>
public interface IDeviceEnricher
{
    string Name { get; }
    Task EnrichAsync(Device device, EnrichContext ctx, CancellationToken ct);
}

/// <summary>
/// Guesses the device type (Android phone, printer, switch...). Every classifier adds points
/// to candidate types; the type with the most points wins. Add your own rules by writing another one.
/// </summary>
public interface IDeviceClassifier
{
    void Score(Device device, TypeScores scores);
}

public sealed class TypeScores
{
    private readonly Dictionary<string, (int Score, List<string> Why)> _s = new();
    public void Add(string type, int points, string why)
    {
        if (!_s.TryGetValue(type, out var v)) v = (0, new List<string>());
        v.Why.Add(why);
        _s[type] = (v.Score + points, v.Why);
    }
    /// <summary>Points a type has so far (0 when none).</summary>
    public int Get(string type) => _s.TryGetValue(type, out var v) ? v.Score : 0;
    public (string Type, int Score, List<string> Why)? Best =>
        _s.Count == 0 ? null : _s.OrderByDescending(kv => kv.Value.Score).Select(kv => (kv.Key, kv.Value.Score, kv.Value.Why)).First();
}

public sealed record DeviceAction(string Group, string Title, Action Execute, string? Tooltip = null);

public sealed class CaptureContext
{
    public required Adapter Adapter { get; init; }
    public required DeviceStore Store { get; init; }
    public required NetworkEngine Engine { get; init; }
}

public sealed class ScanContext
{
    public required NetworkEngine Engine { get; init; }
    public required IReadOnlyList<Adapter> Adapters { get; init; }
    public required Settings Settings { get; init; }
    public required IProgress<string> Status { get; init; }
    /// <summary>Ranges typed in the Range box; empty = automatic (own subnets).</summary>
    public IReadOnlyList<IpRange> Ranges { get; init; } = Array.Empty<IpRange>();
    public DeviceStore Store => Engine.Store;
    public void Log(string msg) => Engine.Log(msg);
}

public sealed class EnrichContext
{
    public required NetworkEngine Engine { get; init; }
    public required Settings Settings { get; init; }
}
