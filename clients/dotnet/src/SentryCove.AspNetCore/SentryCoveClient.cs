using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SentryCove.AspNetCore;

internal sealed record InspectPayload(
    string Method,
    string Scheme,
    string Host,
    string Target,
    IReadOnlyList<string[]> Headers,
    string? PeerIp);

internal sealed record ReportPayload(string ClientIp, string Method, string Target, string Agent, int Status);

internal sealed class AgentPayload
{
    public string? Kind { get; set; }

    public string? Name { get; set; }

    public string? Label { get; set; }
}

internal sealed class DecisionPayload
{
    public string? Action { get; set; }

    public int? Status { get; set; }

    public AgentPayload? Agent { get; set; }

    public string? ClientIp { get; set; }

    public bool ReportResponse { get; set; }

    public bool Degraded { get; set; }
}

internal sealed record Decision(
    bool Block,
    int Status,
    AgentIdentity Agent,
    string? ClientIp,
    bool ReportResponse,
    bool Degraded);

/// <summary>Talks to the SentryCove decision API (<c>sentrycove sidecar</c>).</summary>
internal sealed class SentryCoveClient
{
    internal const string HttpClientName = "SentryCove";

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    private static readonly HashSet<string> Kinds = new(StringComparer.Ordinal)
    {
        "verified", "declared", "automation", "unclassified",
    };

    private readonly IHttpClientFactory _factory;
    private readonly SentryCoveOptions _options;
    private readonly ILogger<SentryCoveClient> _logger;
    private long _lastWarningTicks;

    public SentryCoveClient(
        IHttpClientFactory factory,
        IOptions<SentryCoveOptions> options,
        ILogger<SentryCoveClient> logger)
    {
        _factory = factory;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// Ask for a verdict. Never throws for decision API problems: the result is then a
    /// degraded decision chosen by <see cref="SentryCoveOptions.FailOpen"/>.
    /// Throws <see cref="OperationCanceledException"/> only when the caller's own request was aborted.
    /// </summary>
    public async Task<Decision> InspectAsync(InspectPayload payload, CancellationToken requestAborted)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(requestAborted);
        timeout.CancelAfter(_options.Timeout);
        try
        {
            using var response = await _factory.CreateClient(HttpClientName)
                .PostAsJsonAsync("v1/inspect", payload, Json, timeout.Token)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"decision API answered HTTP {(int)response.StatusCode}");
            }

            var body = await response.Content.ReadFromJsonAsync<DecisionPayload>(Json, timeout.Token)
                .ConfigureAwait(false);
            return Parse(body);
        }
        catch (OperationCanceledException) when (requestAborted.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException
                                       or InvalidOperationException or NotSupportedException)
        {
            WarnThrottled(ex);
            return Fallback();
        }
    }

    /// <summary>Report the app's response status (used for failed-login monitoring). Never throws.</summary>
    public async Task ReportAsync(ReportPayload payload)
    {
        try
        {
            using var timeout = new CancellationTokenSource(_options.Timeout);
            using var response = await _factory.CreateClient(HttpClientName)
                .PostAsJsonAsync("v1/response", payload, Json, timeout.Token)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"decision API answered HTTP {(int)response.StatusCode}");
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException
                                       or InvalidOperationException or NotSupportedException)
        {
            WarnThrottled(ex);
        }
    }

    private Decision Fallback() => _options.FailOpen
        ? new Decision(false, 0, AgentIdentity.Unclassified, null, false, true)
        : new Decision(true, StatusCodes.Status503ServiceUnavailable, AgentIdentity.Unclassified, null, false, true);

    private static Decision Parse(DecisionPayload? body)
    {
        if (body is null || (body.Action != "allow" && body.Action != "block"))
        {
            throw new JsonException("decision API returned an unexpected body");
        }

        var kind = body.Agent?.Kind is { } k && Kinds.Contains(k) ? k : "unclassified";
        var name = body.Agent?.Name;
        var label = body.Agent?.Label ?? (name is null ? kind : $"{kind}:{name}");
        var block = body.Action == "block";
        var status = body.Status is >= 400 and <= 599 ? body.Status.Value : StatusCodes.Status403Forbidden;
        return new Decision(
            block,
            block ? status : 0,
            new AgentIdentity(kind, name, label),
            body.ClientIp,
            body.ReportResponse,
            body.Degraded);
    }

    private void WarnThrottled(Exception ex)
    {
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref _lastWarningTicks);
        if (last != 0 && now - last < 30_000)
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _lastWarningTicks, now, last) == last)
        {
            _logger.LogWarning("SentryCove decision API unavailable: {Reason}", ex.Message);
        }
    }
}
