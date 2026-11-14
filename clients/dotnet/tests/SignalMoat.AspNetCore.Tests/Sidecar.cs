using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SignalMoat.AspNetCore.Tests;

/// <summary>Runs the real SignalMoat decision API (<c>python -m signalmoat sidecar</c>) for the tests.</summary>
internal sealed class Sidecar : IAsyncDisposable
{
    public const string Token = "dotnet-test-token-0123456789abcdef";

    private const string Policy = """
        {
          "mode": "enforce",
          "rules": [
            {"name": "no-bot-forms", "paths": ["/contact"], "methods": ["POST"],
             "agents": ["declared", "automation"], "action": "block", "severity": "high"}
          ],
          "honeypots": {"paths": ["/.env"], "ban_seconds": 0},
          "login": {"paths": ["/login"], "per_ip_threshold": 3, "global_threshold": 1000},
          "alerts": {"sinks": [{"type": "log", "min_severity": "low"}], "cooldown_seconds": 0}
        }
        """;

    private readonly Process _process;
    private readonly StringBuilder _log = new();
    private readonly string _directory;

    private Sidecar(Process process, Uri url, string directory)
    {
        _process = process;
        Url = url;
        _directory = directory;
    }

    public Uri Url { get; }

    public string Log
    {
        get
        {
            lock (_log)
            {
                return _log.ToString();
            }
        }
    }

    public static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public static async Task<Sidecar> StartAsync()
    {
        var directory = Directory.CreateTempSubdirectory("signalmoat-").FullName;
        var policyPath = Path.Combine(directory, "policy.yaml");
        await File.WriteAllTextAsync(policyPath, Policy); // JSON is valid YAML

        var port = FreePort();
        var info = new ProcessStartInfo(Environment.GetEnvironmentVariable("SIGNALMOAT_PYTHON") ?? "python3")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in new[] { "-m", "signalmoat", "sidecar", "--config", policyPath, "--port", port.ToString() })
        {
            info.ArgumentList.Add(argument);
        }

        info.Environment["SIGNALMOAT_API_TOKEN"] = Token;
        var process = Process.Start(info) ?? throw new InvalidOperationException("could not start python");
        var sidecar = new Sidecar(process, new Uri($"http://127.0.0.1:{port}"), directory);
        process.OutputDataReceived += (_, e) => sidecar.Append(e.Data);
        process.ErrorDataReceived += (_, e) => sidecar.Append(e.Data);
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var http = new HttpClient(new SocketsHttpHandler { UseProxy = false });
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (true)
        {
            if (process.HasExited)
            {
                throw new InvalidOperationException($"decision API exited early:\n{sidecar.Log}");
            }

            try
            {
                using var response = await http.GetAsync(new Uri(sidecar.Url, "/_signalmoat/health"));
                if (response.IsSuccessStatusCode)
                {
                    return sidecar;
                }
            }
            catch (HttpRequestException)
            {
                // not listening yet
            }

            if (DateTime.UtcNow > deadline)
            {
                await sidecar.DisposeAsync();
                throw new TimeoutException($"decision API did not start:\n{sidecar.Log}");
            }

            await Task.Delay(100);
        }
    }

    /// <summary>Wait until the decision API has logged <paramref name="text"/> (alerts are log lines).</summary>
    public async Task WaitForLogAsync(string text)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!Log.Contains(text, StringComparison.Ordinal))
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException($"\"{text}\" never appeared in the decision API log:\n{Log}");
            }

            await Task.Delay(25);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (!_process.HasExited)
        {
            _process.Kill(entireProcessTree: true);
            await _process.WaitForExitAsync();
        }

        _process.Dispose();
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // best effort
        }
    }

    private void Append(string? line)
    {
        if (line is null)
        {
            return;
        }

        lock (_log)
        {
            _log.AppendLine(line);
        }
    }
}
