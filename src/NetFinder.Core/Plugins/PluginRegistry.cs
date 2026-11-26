using System.Reflection;

namespace NetFinder.Core.Plugins;

/// <summary>Finds all analyzers / scanners / actions / enrichers by reflection.</summary>
public sealed class PluginRegistry
{
    public List<IPacketAnalyzer> Analyzers { get; } = new();
    public List<IActiveScanner> Scanners { get; } = new();
    public List<IDeviceActionProvider> ActionProviders { get; } = new();
    public List<IDeviceEnricher> Enrichers { get; } = new();
    public List<IDeviceClassifier> Classifiers { get; } = new();
    public List<string> LoadErrors { get; } = new();

    public static string PluginFolder => Path.Combine(AppContext.BaseDirectory, "plugins");

    public void LoadFrom(IEnumerable<Assembly> assemblies, bool includePluginFolder = true)
    {
        var list = assemblies.Distinct().ToList();
        if (includePluginFolder && Directory.Exists(PluginFolder))
        {
            foreach (var dll in Directory.GetFiles(PluginFolder, "*.dll"))
            {
                try { list.Add(Assembly.LoadFrom(dll)); }
                catch (Exception ex) { LoadErrors.Add($"{Path.GetFileName(dll)}: {ex.Message}"); }
            }
        }

        foreach (var asm in list)
        {
            Type[] types;
            try { types = asm.GetTypes(); }
            catch (ReflectionTypeLoadException ex) { types = ex.Types.Where(t => t != null).ToArray()!; }
            foreach (var t in types)
            {
                if (t.IsAbstract || t.IsInterface || t.GetConstructor(Type.EmptyTypes) == null) continue;
                if (t.GetCustomAttribute<DisabledPluginAttribute>() != null) continue;
                try
                {
                    object? inst = null;
                    object Get() => inst ??= Activator.CreateInstance(t)!;
                    if (typeof(IPacketAnalyzer).IsAssignableFrom(t)) Analyzers.Add((IPacketAnalyzer)Get());
                    if (typeof(IActiveScanner).IsAssignableFrom(t)) Scanners.Add((IActiveScanner)Get());
                    if (typeof(IDeviceActionProvider).IsAssignableFrom(t)) ActionProviders.Add((IDeviceActionProvider)Get());
                    if (typeof(IDeviceEnricher).IsAssignableFrom(t)) Enrichers.Add((IDeviceEnricher)Get());
                    if (typeof(IDeviceClassifier).IsAssignableFrom(t)) Classifiers.Add((IDeviceClassifier)Get());
                }
                catch (Exception ex) { LoadErrors.Add($"{t.Name}: {ex.Message}"); }
            }
        }
        Scanners.Sort((a, b) => a.Order.CompareTo(b.Order));
    }
}

/// <summary>Put this on a plugin class to switch it off without deleting it.</summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class DisabledPluginAttribute : Attribute { }
