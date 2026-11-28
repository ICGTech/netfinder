namespace NetFinder.Core.Model;

/// <summary>Device type names. Add new ones freely; the UI shows whatever string a classifier returns.</summary>
public static class DeviceTypes
{
    public const string Unknown = "Unknown";
    public const string Router = "Router / Gateway";
    public const string Switch = "Switch";
    public const string AccessPoint = "Access point";
    public const string Firewall = "Firewall";
    public const string Printer = "Printer";
    public const string Camera = "IP camera";
    public const string Nvr = "NVR / DVR";
    public const string Tv = "TV / Media player";
    public const string Android = "Android phone/tablet";
    public const string IPhone = "iPhone / iPad";
    public const string Mac = "Mac";
    public const string WindowsPc = "Windows PC";
    public const string WindowsServer = "Windows Server";
    public const string Linux = "Linux / Server";
    public const string Nas = "NAS / Storage";
    public const string Iot = "Smart home / IoT";
    public const string VoipPhone = "IP phone";
    public const string Console = "Game console";
    public const string Vm = "Virtual machine";
    public const string Phone = "Phone (private MAC)";
    public const string Ups = "UPS / Power";
    public const string AccessControl = "Access control / Attendance";

    public static readonly string[] All =
    {
        Router, Switch, AccessPoint, Firewall, Printer, Camera, Nvr, Tv, Android, IPhone, Mac, WindowsPc,
        WindowsServer, Linux, Nas, Iot, VoipPhone, Console, Vm, Phone, Ups, AccessControl, Unknown,
    };
}
