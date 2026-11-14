using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace SentryCove.AspNetCore;

/// <summary>Registration helpers for the SentryCove middleware.</summary>
public static class SentryCoveExtensions
{
    /// <summary>
    /// Registers SentryCove. Call <see cref="UseSentryCove"/> afterwards to add it to the pipeline.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddSentryCove(options =>
    /// {
    ///     options.Url = new Uri("http://127.0.0.1:8787");
    ///     options.Token = builder.Configuration["SentryCove:Token"];
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddSentryCove(this IServiceCollection services, Action<SentryCoveOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<SentryCoveOptions>().Configure(configure).ValidateOnStart();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<SentryCoveOptions>, SentryCoveOptionsValidator>());

        services.AddHttpClient(SentryCoveClient.HttpClientName)
            .ConfigureHttpClient((provider, http) =>
            {
                var options = provider.GetRequiredService<IOptions<SentryCoveOptions>>().Value;
                var baseUrl = options.Url!.AbsoluteUri;
                http.BaseAddress = new Uri(baseUrl.EndsWith('/') ? baseUrl : baseUrl + "/");
                http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", options.Token);
                // Per-call timeouts are applied by SentryCoveClient.
                http.Timeout = System.Threading.Timeout.InfiniteTimeSpan;
            })
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                // The decision API is a local service: never route it through a system proxy.
                UseProxy = false,
                AllowAutoRedirect = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            });

        services.TryAddSingleton<SentryCoveClient>();
        return services;
    }

    /// <summary>
    /// Adds SentryCove to the request pipeline. Place it early: after
    /// <c>UseForwardedHeaders</c> (if you use it) and before routing, authentication and your endpoints.
    /// </summary>
    public static IApplicationBuilder UseSentryCove(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (app.ApplicationServices.GetService<SentryCoveClient>() is null)
        {
            throw new InvalidOperationException(
                "SentryCove is not registered. Call builder.Services.AddSentryCove(...) before app.UseSentryCove().");
        }

        return app.UseMiddleware<SentryCoveMiddleware>();
    }

    /// <summary>
    /// Who SentryCove thinks is making this request, or <c>null</c> if the middleware has not run.
    /// </summary>
    public static AgentIdentity? GetSentryCoveAgent(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.Items.TryGetValue(SentryCoveMiddleware.AgentItemKey, out var value) ? value as AgentIdentity : null;
    }
}

internal sealed class SentryCoveOptionsValidator : IValidateOptions<SentryCoveOptions>
{
    public ValidateOptionsResult Validate(string? name, SentryCoveOptions options)
    {
        var error = options.Validate();
        return error is null ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(error);
    }
}
