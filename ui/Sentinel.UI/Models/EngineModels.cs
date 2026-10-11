using System.Text.Json.Serialization;

namespace Sentinel.UI.Models;

/// <summary>Mirror of the engine verdict payload (ipc/protocol.md).</summary>
public sealed class Verdict
{
    [JsonPropertyName("level")] public string Level { get; set; } = "Unknown";
    [JsonPropertyName("action")] public string Action { get; set; } = "Allow";
    [JsonPropertyName("score")] public double Score { get; set; }
    [JsonPropertyName("summary")] public string Summary { get; set; } = "";
    [JsonPropertyName("signals")] public List<Signal> Signals { get; set; } = new();
}

public sealed class Signal
{
    [JsonPropertyName("source")] public string Source { get; set; } = "";
    [JsonPropertyName("level")] public string Level { get; set; } = "";
    [JsonPropertyName("confidence")] public double Confidence { get; set; }
    [JsonPropertyName("detail")] public string Detail { get; set; } = "";
    [JsonPropertyName("rule_id")] public string RuleId { get; set; } = "";
}

/// <summary>A detection surfaced to the dashboard/tray.</summary>
public sealed class Detection
{
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public string Path { get; set; } = "";
    public uint Pid { get; set; }
    public Verdict Verdict { get; set; } = new();
    public bool Quarantined { get; set; }

    public string DisplayTime => TimestampUtc.ToLocalTime().ToString("HH:mm:ss");
    public string Title => string.IsNullOrEmpty(Path) ? $"PID {Pid}" : Path;
}

public sealed class EngineStatus
{
    public bool ProtectionOn { get; set; }
    public string EngineVersion { get; set; } = "";
    public string SignatureVersion { get; set; } = "";
    public DateTime LastUpdateUtc { get; set; }
    public long FilesScanned { get; set; }
    public long ThreatsBlocked { get; set; }
    public long Quarantined { get; set; }
    public bool Isolated { get; set; }

    public string ProtectionText => ProtectionOn ? "Protected" : "At risk";
    public string IsolationText => Isolated ? "Network isolated (containment active)" : "";
}

public sealed class QuarantineItem
{
    public string Id { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public string Reason { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public DateTime QuarantinedUtc { get; set; }

    public string DisplayTime => QuarantinedUtc.ToLocalTime().ToString("g");
}
