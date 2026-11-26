using System.Reflection;
using NetFinder.Core.Model;

namespace NetFinder.Ui;

internal static class Theme
{
    public static readonly Font Base = new("Segoe UI", 9f);
    public static readonly Font Bold = new("Segoe UI Semibold", 9f);
    public static readonly Font Title = new("Segoe UI Semibold", 15f);
    public static readonly Font Small = new("Segoe UI", 8.25f);

    public static readonly Color Accent = Color.FromArgb(0, 120, 212);
    public static readonly Color Brand = Color.FromArgb(18, 32, 58);
    public static readonly Color OtherSubnet = Color.FromArgb(255, 244, 229);
    public static readonly Color OtherSubnetText = Color.FromArgb(176, 84, 0);
    public static readonly Color Good = Color.FromArgb(16, 124, 16);
    public static readonly Color Muted = Color.FromArgb(96, 96, 96);
    public static readonly Color Panel = Color.FromArgb(246, 248, 250);

    private static readonly Dictionary<string, Color> TypeColors = new()
    {
        [DeviceTypes.Router] = Color.FromArgb(0, 120, 212),
        [DeviceTypes.Switch] = Color.FromArgb(0, 99, 177),
        [DeviceTypes.AccessPoint] = Color.FromArgb(0, 153, 188),
        [DeviceTypes.Firewall] = Color.FromArgb(196, 43, 28),
        [DeviceTypes.Printer] = Color.FromArgb(135, 100, 184),
        [DeviceTypes.Camera] = Color.FromArgb(202, 80, 16),
        [DeviceTypes.Nvr] = Color.FromArgb(160, 60, 10),
        [DeviceTypes.Tv] = Color.FromArgb(194, 57, 179),
        [DeviceTypes.Android] = Color.FromArgb(16, 137, 62),
        [DeviceTypes.IPhone] = Color.FromArgb(70, 70, 70),
        [DeviceTypes.Mac] = Color.FromArgb(90, 90, 90),
        [DeviceTypes.WindowsPc] = Color.FromArgb(0, 90, 158),
        [DeviceTypes.Linux] = Color.FromArgb(200, 140, 0),
        [DeviceTypes.Nas] = Color.FromArgb(73, 130, 5),
        [DeviceTypes.Iot] = Color.FromArgb(0, 128, 128),
        [DeviceTypes.VoipPhone] = Color.FromArgb(107, 105, 214),
        [DeviceTypes.Console] = Color.FromArgb(16, 124, 16),
        [DeviceTypes.Vm] = Color.FromArgb(120, 120, 160),
        [DeviceTypes.Phone] = Color.FromArgb(60, 150, 90),
        [DeviceTypes.Ups] = Color.FromArgb(150, 110, 40),
        [DeviceTypes.AccessControl] = Color.FromArgb(150, 60, 100),
    };

    public static Color ForType(string type) => TypeColors.TryGetValue(type, out var c) ? c : Color.FromArgb(150, 150, 150);

    public static Image? Logo()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("logo.png");
        return s == null ? null : Image.FromStream(new MemoryStream(ReadAll(s)));
    }

    public static Icon? AppIcon()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico");
        return s == null ? null : new Icon(new MemoryStream(ReadAll(s)));
    }

    private static byte[] ReadAll(Stream s) { using var m = new MemoryStream(); s.CopyTo(m); return m.ToArray(); }
}
