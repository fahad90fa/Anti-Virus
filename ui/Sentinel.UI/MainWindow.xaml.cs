using System.Windows;
using Sentinel.UI.Services;
using Sentinel.UI.ViewModels;

namespace Sentinel.UI;

public partial class MainWindow : Window
{
    private readonly EngineClient _engine = new();
    private readonly DashboardViewModel _vm;

    public MainWindow()
    {
        InitializeComponent();
        _vm = new DashboardViewModel(_engine);
        DataContext = _vm;
        Loaded += async (_, _) => await _vm.InitializeAsync();
        Closed += (_, _) => _engine.Dispose();
    }
}
