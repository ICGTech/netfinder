namespace NetFinder.Core.Model;

/// <summary>One toner / ink / drum / waste box of a printer (Printer-MIB prtMarkerSuppliesTable).</summary>
/// <param name="Color">"black", "cyan", "magenta", "yellow"… or null when it has no color (drum, fuser, waste box).</param>
/// <param name="Percent">0–100 when the printer tells a level; for a waste box it is how FULL it is.</param>
/// <param name="State">"OK", "Low", "Empty", "Full", "Unknown": what to show when there is no percent.</param>
/// <param name="FillsUp">Waste toner box and the like: it fills up instead of running out.</param>
/// <param name="IsColorant">Toner, ink, ribbon: the ones bought most often (shown first, used in lists).</param>
public sealed record PrinterSupply(string Name, string? Color, int? Percent, string State, bool FillsUp, bool IsColorant)
{
    /// <summary>The printer's own words when they say more than <see cref="Name"/> ("Black Cartridge HP CF410A": the part to order).</summary>
    public string? Detail { get; init; }

    /// <summary>Needs attention: 10 % or less left (or 90 % full for a waste box), or the printer says low / empty.</summary>
    public bool Low => FillsUp ? Percent >= 90 || State == "Full" : Percent <= 10 || State is "Low" or "Empty";

    /// <summary>"Black 45%" / "Waste toner 30% full" / "Drum OK".</summary>
    public string Text => $"{Name} {(Percent is { } p ? FillsUp ? $"{p}% full" : $"{p}%" : State)}";
}

/// <summary>What a printer told over SNMP: supplies, pages printed, its status. Replaced as a whole on each read.</summary>
public sealed record PrinterState(IReadOnlyList<PrinterSupply> Supplies, long? Pages, string? Status, IReadOnlyList<string> Alerts, DateTime ReadAt)
{
    /// <summary>"Black 45% · Cyan 80% · Magenta 9% · Yellow 60%" (the colorants), for lists and exports.</summary>
    public string SuppliesText => string.Join(" · ", Supplies.Where(s => s.IsColorant).DefaultIfEmpty().Where(s => s != null).Select(s => s!.Text));
}

/// <summary>One port of a switch (IF-MIB + BRIDGE-MIB).</summary>
public sealed record SwitchPort(int IfIndex, string Name, string? Alias, bool Up, bool Disabled, long SpeedMbps, IReadOnlyList<string> Macs, IReadOnlyList<int> Vlans)
{
    /// <summary>"1 Gbps", "100 Mbps", "" when unknown or down.</summary>
    public string SpeedText => !Up || SpeedMbps <= 0 ? "" : SpeedMbps >= 1000 ? $"{SpeedMbps / 1000.0:0.#} Gbps" : $"{SpeedMbps} Mbps";
    public string StatusText => Disabled ? "Disabled" : Up ? "Up" : "Down";
}

/// <summary>
/// What a switch (or router) told over SNMP: its ports with the MAC addresses learned on each, and its ARP table
/// (IP → MAC, on routers and layer-3 switches). Replaced as a whole on each read.
/// </summary>
public sealed record SwitchState(IReadOnlyList<SwitchPort> Ports, IReadOnlyDictionary<string, string> Arp, bool IsBridge, DateTime ReadAt)
{
    public int Up => Ports.Count(p => p.Up);
    public int MacCount => Ports.Sum(p => p.Macs.Count);
}
