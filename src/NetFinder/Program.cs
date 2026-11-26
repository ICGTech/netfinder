using NetFinder.Core;

namespace NetFinder;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) =>
            MessageBox.Show(e.Exception.Message, AppInfo.Name + " – error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        Application.Run(new Ui.MainForm());
    }
}
