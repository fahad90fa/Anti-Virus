using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace Sentinel.Tray;

/// <summary>
/// System-tray presence for Sentinel AV. Shows a status icon, reflects
/// protection state, raises toast notifications on detection, and opens the full
/// dashboard on double-click. Connects to the engine over the IPC channel for
/// status; here it is kept minimal and self-contained.
/// </summary>
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        using var app = new TrayApp();
        Application.Run();
    }
}

internal sealed class TrayApp : IDisposable
{
    private readonly NotifyIcon _icon;
    private bool _protected = true;

    public TrayApp()
    {
        _icon = new NotifyIcon
        {
            Visible = true,
            Text = "Sentinel AV — Protected",
            Icon = SystemIcons.Shield,
            ContextMenuStrip = BuildMenu(),
        };
        _icon.DoubleClick += (_, _) => OpenDashboard();
        ShowBalloon("Sentinel AV", "Real-time protection is on.");
    }

    private ContextMenuStrip BuildMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open dashboard", null, (_, _) => OpenDashboard());
        menu.Items.Add("Run self-test", null, (_, _) =>
            ShowBalloon("Sentinel AV", "Self-test requested. See the dashboard for results."));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Protection: on/off", null, (_, _) => ToggleProtection());
        menu.Items.Add("Exit tray", null, (_, _) => { _icon.Visible = false; Application.Exit(); });
        return menu;
    }

    private void ToggleProtection()
    {
        _protected = !_protected;
        _icon.Text = _protected ? "Sentinel AV — Protected" : "Sentinel AV — AT RISK";
        _icon.Icon = _protected ? SystemIcons.Shield : SystemIcons.Warning;
        ShowBalloon("Sentinel AV",
            _protected ? "Real-time protection is on." : "Protection is OFF.");
    }

    /// <summary>Raise a detection toast (called by the IPC event reader).</summary>
    public void NotifyDetection(string target, string verdict)
        => ShowBalloon("Threat blocked", $"{verdict}: {target}");

    private void ShowBalloon(string title, string text)
    {
        _icon.BalloonTipTitle = title;
        _icon.BalloonTipText = text;
        _icon.ShowBalloonTip(4000);
    }

    private static void OpenDashboard()
    {
        try
        {
            var exe = Path.Combine(AppContext.BaseDirectory, "Sentinel.UI.exe");
            Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true });
        }
        catch { /* dashboard not installed alongside the tray in this build */ }
    }

    public void Dispose() => _icon.Dispose();
}
