using NetFinder.Core.Actions;
using NetFinder.Core.Model;
using NetFinder.Core.Net;
using NetFinder.Core.Plugins;

namespace SamplePlugin;

/// <summary>Adds a "PuTTY" button for devices with SSH or Telnet open.</summary>
public sealed class PuttyAction : IDeviceActionProvider
{
    public IEnumerable<DeviceAction> GetActions(Device d)
    {
        if (d.Ip == null) yield break;
        if (d.OpenPorts.Contains(22)) yield return new DeviceAction("Remote", "PuTTY (SSH)", () => Launcher.Run("putty.exe", $"-ssh {d.Ip}"));
        if (d.OpenPorts.Contains(23)) yield return new DeviceAction("Remote", "PuTTY (Telnet)", () => Launcher.Run("putty.exe", $"-telnet {d.Ip}"));
    }
}

/// <summary>Example classifier: devices whose name starts with "POS-" are cash registers.</summary>
public sealed class PosClassifier : IDeviceClassifier
{
    public void Score(Device d, TypeScores s)
    {
        if ((d.Hostname ?? "").StartsWith("POS-", StringComparison.OrdinalIgnoreCase)) s.Add("POS / Cash register", 90, "name starts with POS-");
    }
}

/// <summary>Example analyzer: logs any device that sends Wake-on-LAN magic packets (UDP 9).</summary>
public sealed class WakeOnLanAnalyzer : IPacketAnalyzer
{
    public string Name => "Wake-on-LAN";

    public void Analyze(Frame f, CaptureContext ctx)
    {
        if (f.IsUdp && f.DstPort == 9 && f.UdpPayloadLength >= 102)
            ctx.Store.Observe(f.SrcMac, "WoL", ctx.Adapter, f.SrcIp, d => d.Info["Sent Wake-on-LAN"] = f.Time.ToString("HH:mm:ss"));
    }
}
