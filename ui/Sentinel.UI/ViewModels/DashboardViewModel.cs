using System.Collections.ObjectModel;
using System.Text.Json;
using Sentinel.UI.Models;
using Sentinel.UI.Services;

namespace Sentinel.UI.ViewModels;

/// <summary>
/// Backs the main dashboard: live protection status, recent detections, the
/// quarantine list, and the user actions (scan, restore, self-test). All engine
/// communication goes through <see cref="EngineClient"/>.
/// </summary>
public sealed class DashboardViewModel : ViewModelBase
{
    private readonly EngineClient _engine;
    private EngineStatus _status = new();
    private string _connectionState = "Connecting…";

    public DashboardViewModel(EngineClient engine)
    {
        _engine = engine;
        RefreshCommand = new RelayCommand(RefreshAsync);
        SelfTestCommand = new RelayCommand(RunSelfTestAsync);
        ScanCommand = new RelayCommand(ScanAsync, () => !string.IsNullOrWhiteSpace(ScanPath));
    }

    public ObservableCollection<Detection> Detections { get; } = new();
    public ObservableCollection<QuarantineItem> Quarantine { get; } = new();

    public EngineStatus Status
    {
        get => _status;
        private set { SetField(ref _status, value); OnPropertyChanged(nameof(ProtectionBannerText)); }
    }

    public string ConnectionState
    {
        get => _connectionState;
        private set => SetField(ref _connectionState, value);
    }

    private string _scanPath = "";
    public string ScanPath
    {
        get => _scanPath;
        set { if (SetField(ref _scanPath, value)) ScanCommand.RaiseCanExecuteChanged(); }
    }

    public string ProtectionBannerText =>
        Status.ProtectionOn ? "You are protected" : "Protection is off — you are at risk";

    public RelayCommand RefreshCommand { get; }
    public RelayCommand SelfTestCommand { get; }
    public RelayCommand ScanCommand { get; }

    public async Task InitializeAsync()
    {
        ConnectionState = await _engine.ConnectAsync().ConfigureAwait(true)
            ? "Connected to engine"
            : "Engine not reachable (is the service running?)";
        if (_engine.IsConnected)
            await RefreshAsync().ConfigureAwait(true);
    }

    private async Task RefreshAsync()
    {
        if (!_engine.IsConnected) return;
        try
        {
            var reply = await _engine.RequestAsync("get_status").ConfigureAwait(true);
            if (reply.TryGetProperty("status", out var s))
                Status = JsonSerializer.Deserialize<EngineStatus>(s.GetRawText()) ?? new();

            var q = await _engine.RequestAsync("list_quarantine").ConfigureAwait(true);
            Quarantine.Clear();
            if (q.TryGetProperty("items", out var items))
                foreach (var it in items.EnumerateArray())
                    Quarantine.Add(JsonSerializer.Deserialize<QuarantineItem>(it.GetRawText())!);
        }
        catch { ConnectionState = "Lost connection to engine"; }
    }

    private async Task RunSelfTestAsync()
    {
        if (!_engine.IsConnected) return;
        var reply = await _engine.RequestAsync("run_selftest").ConfigureAwait(true);
        bool passed = reply.TryGetProperty("passed", out var p) && p.GetBoolean();
        ConnectionState = passed
            ? "Self-test passed: EICAR detected, clean file allowed"
            : "Self-test FAILED — check the engine logs";
    }

    private async Task ScanAsync()
    {
        if (!_engine.IsConnected || string.IsNullOrWhiteSpace(ScanPath)) return;
        var reply = await _engine.RequestAsync("scan_path",
            new { path = ScanPath, recursive = true }).ConfigureAwait(true);
        if (reply.TryGetProperty("malicious", out var m))
            ConnectionState = $"Scan complete: {m.GetInt32()} malicious found";
        await RefreshAsync().ConfigureAwait(true);
    }

    /// <summary>Called by the event-reader when the engine pushes a detection.</summary>
    public void OnDetection(Detection d)
    {
        Detections.Insert(0, d);
        while (Detections.Count > 200) Detections.RemoveAt(Detections.Count - 1);
    }
}
