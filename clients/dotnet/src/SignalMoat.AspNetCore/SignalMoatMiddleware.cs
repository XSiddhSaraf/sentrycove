using Microsoft.AspNetCore.Http.Features;

namespace SignalMoat.AspNetCore;

internal sealed class SignalMoatMiddleware
{
    internal static readonly object AgentItemKey = new();

    private const string BlockedBody = "{\"error\": \"request blocked\"}";
    private const string UnavailableBody = "{\"error\": \"request could not be screened\"}";

    private readonly RequestDelegate _next;
    private readonly SignalMoatClient _client;

    public SignalMoatMiddleware(RequestDelegate next, SignalMoatClient client)
    {
        _next = next;
        _client = client;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;
        var target = RequestTarget(context);
        var decision = await _client.InspectAsync(
            new InspectPayload(
                request.Method,
                request.Scheme,
                request.Host.Value ?? string.Empty,
                target,
                HeaderPairs(request.Headers),
                PeerAddress(context)),
            context.RequestAborted).ConfigureAwait(false);

        context.Items[AgentItemKey] = decision.Agent;

        if (decision.Block)
        {
            var response = context.Response;
            response.StatusCode = decision.Status;
            response.ContentType = "application/json";
            response.Headers.CacheControl = "no-store";
            await response.WriteAsync(decision.Degraded ? UnavailableBody : BlockedBody, context.RequestAborted)
                .ConfigureAwait(false);
            return;
        }

        if (decision.ReportResponse && decision.ClientIp is { } clientIp)
        {
            var method = request.Method;
            var agent = decision.Agent.Label;
            context.Response.OnCompleted(() =>
            {
                // Fire and forget: reporting must never delay or fail the response.
                _ = _client.ReportAsync(new ReportPayload(clientIp, method, target, agent, context.Response.StatusCode));
                return Task.CompletedTask;
            });
        }

        await _next(context).ConfigureAwait(false);
    }

    /// <summary>
    /// The request target as the client sent it ("/path?query"), so SignalMoat judges the same
    /// bytes the server routed. Absolute-form targets fall back to the parsed path.
    /// </summary>
    private static string RequestTarget(HttpContext context)
    {
        var raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (!string.IsNullOrEmpty(raw) && raw[0] == '/')
        {
            return raw;
        }

        var request = context.Request;
        var rebuilt = request.PathBase.Add(request.Path).ToUriComponent() + request.QueryString.ToUriComponent();
        return rebuilt.Length > 0 && rebuilt[0] == '/' ? rebuilt : "/" + rebuilt;
    }

    private static List<string[]> HeaderPairs(IHeaderDictionary headers)
    {
        var pairs = new List<string[]>(headers.Count);
        foreach (var header in headers)
        {
            foreach (var value in header.Value)
            {
                if (value is not null)
                {
                    pairs.Add([header.Key, value]);
                }
            }
        }

        return pairs;
    }

    private static string? PeerAddress(HttpContext context)
    {
        var address = context.Connection.RemoteIpAddress;
        if (address is null)
        {
            return null;
        }

        return (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
    }
}
