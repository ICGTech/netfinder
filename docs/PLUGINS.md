# Extending NetFinder

Everything the program does is a small plugin class. Add a class that implements one of the
interfaces below and it is picked up automatically when the program starts — either:

* **inside the source** (any `.cs` file in `src/NetFinder.Core` or `src/NetFinder`), then rebuild, or
* **as a separate DLL** dropped into the `plugins` folder next to `NetFinder.exe`
  (see `examples/SamplePlugin`; Settings → "Plugins folder" opens it).

| Interface | What it does | Built-in examples |
|---|---|---|
| `IPacketAnalyzer` | Looks at every captured frame and records devices/info | `ArpAnalyzer`, `DhcpAnalyzer`, `MdnsAnalyzer`, `SsdpAnalyzer`, `NetbiosAnalyzer`, `LldpCdpAnalyzer`, `BroadcastAnalyzer` |
| `IActiveScanner` | Sends probes when you press **Scan** (`Order` sets the sequence) | `LocalArpSweep`, `WindowsArpSweep`, `PingTcpSweep`, `OtherSubnetProbe`, `DiscoveryQueries` |
| `IDeviceClassifier` | Adds points to device types (Android, Printer…). Highest total wins | `BuiltInClassifier` |
| `IDeviceActionProvider` | Buttons in the **Device** tab | `BuiltInActions` |
| `IDeviceEnricher` | Runs after a port check (read web titles, banners…) | `WebTitleEnricher`, `NameEnricher` |

To switch a built-in plugin off without deleting it, put `[DisabledPlugin]` on the class.

## Common changes

* **Rename the program**: `src/NetFinder.Core/AppInfo.cs` (name shown everywhere) and `AssemblyName` /
  `Product` in `src/NetFinder/NetFinder.csproj` (the .exe file name).
* **Logo**: replace `src/NetFinder/Assets/app.ico` and `logo-256.png`, or edit and re-run `tools/make_logo.py`.
* **Default subnets / ports**: `src/NetFinder.Core/Model/Settings.cs` (users can also edit them in Settings).
* **Device type rules**: the tables at the top of `src/NetFinder.Core/Classifiers/BuiltInClassifier.cs` —
  one line per rule: `(regex, type, points)`.
* **New type names / colours**: `Model/DeviceTypes.cs` and `src/NetFinder/Ui/Theme.cs`.

## Testing without the GUI

`tests/NetFinder.Probe` is a console app that runs the same engine and prints what it finds:

```
dotnet run --project tests/NetFinder.Probe -- "<adapter id>" 10 scan ports
```
