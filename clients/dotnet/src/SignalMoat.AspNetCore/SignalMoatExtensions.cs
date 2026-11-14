using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace SignalMoat.AspNetCore;

/// <summary>Registration helpers for the SignalMoat middleware.</summary>
public static class SignalMoatExtensions
{
    /// <summary>
    /// Registers SignalMoat. Call <see cref="UseSignalMoat"/> afterwards to add it to the pipeline.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddSignalMoat(options =>
    /// {
    ///     options.Url = new Uri("http://127.0.0.1:8787");
    ///     options.Token = builder.Configuration["SignalMoat:Token"];
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddSignalMoat(this IServiceCollection services, Action<SignalMoatOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<SignalMoatOptions>().Configure(configure).ValidateOnStart();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<SignalMoatOptions>, SignalMoatOptionsValidator>());

        services.AddHttpClient(SignalMoatClient.HttpClientName)
            .ConfigureHttpClient((provider, http) =>
            {
                var options = provider.GetRequiredService<IOptions<SignalMoatOptions>>().Value;
                var baseUrl = options.Url!.AbsoluteUri;
                http.BaseAddress = new Uri(baseUrl.EndsWith('/') ? baseUrl : baseUrl + "/");
                http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", options.Token);
                // Per-call timeouts are applied by SignalMoatClient.
                http.Timeout = System.Threading.Timeout.InfiniteTimeSpan;
            })
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                // The decision API is a local service: never route it through a system proxy.
                UseProxy = false,
                AllowAutoRedirect = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            });

        services.TryAddSingleton<SignalMoatClient>();
        return services;
    }

    /// <summary>
    /// Adds SignalMoat to the request pipeline. Place it early: after
    /// <c>UseForwardedHeaders</c> (if you use it) and before routing, authentication and your endpoints.
    /// </summary>
    public static IApplicationBuilder UseSignalMoat(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (app.ApplicationServices.GetService<SignalMoatClient>() is null)
        {
            throw new InvalidOperationException(
                "SignalMoat is not registered. Call builder.Services.AddSignalMoat(...) before app.UseSignalMoat().");
        }

        return app.UseMiddleware<SignalMoatMiddleware>();
    }

    /// <summary>
    /// Who SignalMoat thinks is making this request, or <c>null</c> if the middleware has not run.
    /// </summary>
    public static AgentIdentity? GetSignalMoatAgent(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.Items.TryGetValue(SignalMoatMiddleware.AgentItemKey, out var value) ? value as AgentIdentity : null;
    }
}

internal sealed class SignalMoatOptionsValidator : IValidateOptions<SignalMoatOptions>
{
    public ValidateOptionsResult Validate(string? name, SignalMoatOptions options)
    {
        var error = options.Validate();
        return error is null ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(error);
    }
}
