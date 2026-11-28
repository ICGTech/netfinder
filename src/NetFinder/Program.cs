using NetFinder.Core;

namespace NetFinder;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        var justUpdated = Core.Update.UpdateChecker.FinishUpdate(args);
        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        var shotDir = Environment.GetEnvironmentVariable("NETFINDER_SCREENSHOT");
        Application.ThreadException += (_, e) =>
        {
            if (!string.IsNullOrEmpty(shotDir))
            {
                // screenshot run: no message box to block it; the error is written down instead
                try { Directory.CreateDirectory(shotDir); File.AppendAllText(Path.Combine(shotDir, "ui-errors.txt"), e.Exception + "\r\n\r\n"); } catch { }
                return;
            }
            MessageBox.Show(e.Exception.Message, AppInfo.Name + " – error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        };
        Application.Run(new Ui.MainForm(justUpdated));
    }
}
