using System.Text.Json;

namespace NetFinder.Core.Model;

/// <summary>Names / types / notes the user gave to devices, remembered by MAC in %AppData%\NetFinder\labels.json.</summary>
public sealed class UserLabels
{
    public sealed class Label
    {
        public string? Name { get; set; }
        public string? Type { get; set; }
        public string? Notes { get; set; }
    }

    public Dictionary<string, Label> ByMac { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    private static string FilePath => Path.Combine(Settings.Folder, "labels.json");

    public static UserLabels Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var l = JsonSerializer.Deserialize<UserLabels>(File.ReadAllText(FilePath));
                if (l != null) { l.ByMac = new(l.ByMac, StringComparer.OrdinalIgnoreCase); return l; }
            }
        }
        catch { }
        return new UserLabels();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Settings.Folder);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    public void Apply(Device d)
    {
        if (!ByMac.TryGetValue(d.LabelKey, out var l)) return;
        d.CustomName = l.Name;
        d.TypeOverride = l.Type;
        d.Notes = l.Notes;
    }

    public void Set(Device d)
    {
        if (d.CustomName == null && d.TypeOverride == null && d.Notes == null) ByMac.Remove(d.LabelKey);
        else ByMac[d.LabelKey] = new Label { Name = d.CustomName, Type = d.TypeOverride, Notes = d.Notes };
        Save();
    }
}
