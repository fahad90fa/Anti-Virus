using System.IO;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.UI.Services;

/// <summary>
/// Client for the engine IPC channel (see ipc/protocol.md). Prefers the Windows
/// named pipe and falls back to the loopback TCP endpoint used by the dev build.
/// Newline-delimited JSON framing. Read-mostly: the UI issues requests and
/// receives replies/events; destructive ops are re-authorized by the engine.
/// </summary>
public sealed class EngineClient : IDisposable
{
    private const string PipeName = "SentinelEngine";
    private const string LoopbackHost = "127.0.0.1";
    private const int LoopbackPort = 51515;

    private Stream? _stream;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private int _nextId = 1;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public bool IsConnected => _stream is not null;

    /// <summary>Connect to the engine, trying the named pipe then TCP loopback.</summary>
    public async Task<bool> ConnectAsync(CancellationToken ct = default)
    {
        try
        {
            var pipe = new NamedPipeClientStream(".", PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(1500, ct).ConfigureAwait(false);
            Bind(pipe);
            return true;
        }
        catch
        {
            // Fall through to the dev TCP endpoint.
        }

        try
        {
            var tcp = new TcpClient();
            await tcp.ConnectAsync(LoopbackHost, LoopbackPort, ct).ConfigureAwait(false);
            Bind(tcp.GetStream());
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void Bind(Stream s)
    {
        _stream = s;
        _reader = new StreamReader(s, Encoding.UTF8);
        _writer = new StreamWriter(s, new UTF8Encoding(false)) { AutoFlush = true };
    }

    /// <summary>Send a request and await the matching reply.</summary>
    public async Task<JsonElement> RequestAsync(string op, object? args = null,
        CancellationToken ct = default)
    {
        if (_writer is null || _reader is null)
            throw new InvalidOperationException("not connected");

        int id = Interlocked.Increment(ref _nextId);
        var envelope = new Dictionary<string, object?>
        {
            ["type"] = "request",
            ["id"] = id,
            ["op"] = op,
        };
        if (args is not null)
        {
            foreach (var p in args.GetType().GetProperties())
                envelope[p.Name] = p.GetValue(args);
        }

        await _writer.WriteLineAsync(JsonSerializer.Serialize(envelope, JsonOpts))
            .ConfigureAwait(false);

        // Read lines until we get the reply with our id (events may interleave;
        // in production events are dispatched on a separate reader task).
        while (!ct.IsCancellationRequested)
        {
            string? line = await _reader.ReadLineAsync().ConfigureAwait(false);
            if (line is null) break;
            var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (root.TryGetProperty("type", out var t) && t.GetString() == "reply"
                && root.TryGetProperty("id", out var rid) && rid.GetInt32() == id)
            {
                return root.Clone();
            }
        }
        throw new IOException("connection closed before reply");
    }

    public void Dispose()
    {
        _writer?.Dispose();
        _reader?.Dispose();
        _stream?.Dispose();
        _stream = null;
    }
}
