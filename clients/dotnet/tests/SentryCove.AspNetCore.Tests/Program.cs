using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Options;
using SentryCove.AspNetCore;

namespace SentryCove.AspNetCore.Tests;

internal static class Program
{
    private const string BrowserUa =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36";

    private static readonly HttpClient Http = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });

    private static async Task<int> Main()
    {
        await using var sidecar = await Sidecar.StartAsync();
        var deadUrl = new Uri($"http://127.0.0.1:{Sidecar.FreePort()}");

        var tests = new (string Name, Func<Task> Run)[]
        {
            ("browsers pass and endpoints can see who is calling", async () =>
            {
                await using var app = await StartAppAsync(o => Configure(o, sidecar.Url));
                using var browser = await SendAsync(app, HttpMethod.Get, "/", BrowserUa);
                Equal(HttpStatusCode.OK, browser.StatusCode);
                Equal("unclassified", await browser.Content.ReadAsStringAsync());

                using var bot = await SendAsync(app, HttpMethod.Get, "/", "Mozilla/5.0 (compatible; GPTBot/1.2)");
                Equal("declared:GPTBot", await bot.Content.ReadAsStringAsync());
            }),

            ("rule blocks stop the request before the endpoint runs", async () =>
            {
                await using var app = await StartAppAsync(o => Configure(o, sidecar.Url));
                using var blocked = await SendAsync(app, HttpMethod.Post, "/contact", "python-requests/2.32");
                Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
                Equal("{\"error\": \"request blocked\"}", await blocked.Content.ReadAsStringAsync());
                Equal("no-store", blocked.Headers.CacheControl?.ToString());
                Equal("application/json", blocked.Content.Headers.ContentType?.MediaType);

                // ASP.NET Core routes all of these to the same endpoint; so must the rule.
                foreach (var path in new[] { "/CONTACT", "/contact/", "/c%6fntact", "/contact?x=1" })
                {
                    using var variant = await SendAsync(app, HttpMethod.Post, path, "python-requests/2.32");
                    Equal(HttpStatusCode.Forbidden, variant.StatusCode, path);
                }

                using var human = await SendAsync(app, HttpMethod.Post, "/contact", BrowserUa);
                Equal("received", await human.Content.ReadAsStringAsync());
            }),

            ("honeypot hits are blocked and raise an alert", async () =>
            {
                await using var app = await StartAppAsync(o => Configure(o, sidecar.Url));
                using var trap = await SendAsync(app, HttpMethod.Get, "/.env", BrowserUa);
                Equal(HttpStatusCode.NotFound, trap.StatusCode);
                True(!(await trap.Content.ReadAsStringAsync()).Contains("SECRET"), "decoy content must not be served");
                await sidecar.WaitForLogAsync("\"type\": \"honeypot_hit\"");
            }),

            ("absolute-form request targets are judged by the path inside them", async () =>
            {
                await using var app = await StartAppAsync(o => Configure(o, sidecar.Url));
                var status = await RawStatusAsync(app.Address, $"GET http://{app.Address.Authority}/.env HTTP/1.1");
                Equal(404, status);
            }),

            ("failed logins are reported and raise a brute-force alert", async () =>
            {
                await using var app = await StartAppAsync(o => Configure(o, sidecar.Url));
                for (var i = 0; i < 3; i++)
                {
                    using var response = await SendAsync(app, HttpMethod.Post, "/login", BrowserUa);
                    Equal(HttpStatusCode.Unauthorized, response.StatusCode);
                }

                await sidecar.WaitForLogAsync("\"type\": \"login_bruteforce\"");
            }),

            ("fail-open lets requests through when the decision API is down", async () =>
            {
                await using var app = await StartAppAsync(o => Configure(o, deadUrl));
                using var response = await SendAsync(app, HttpMethod.Post, "/contact", "curl/8.9");
                Equal(HttpStatusCode.OK, response.StatusCode);
            }),

            ("fail-closed answers 503 when the decision API is down", async () =>
            {
                await using var app = await StartAppAsync(o =>
                {
                    Configure(o, deadUrl);
                    o.FailOpen = false;
                });
                using var response = await SendAsync(app, HttpMethod.Get, "/", BrowserUa);
                Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
                Equal("{\"error\": \"request could not be screened\"}", await response.Content.ReadAsStringAsync());
            }),

            ("a wrong token is an error, not a silent allow", async () =>
            {
                await using var app = await StartAppAsync(o =>
                {
                    Configure(o, sidecar.Url);
                    o.Token = "wrong-token-wrong-token-wrong";
                    o.FailOpen = false;
                });
                using var response = await SendAsync(app, HttpMethod.Get, "/", BrowserUa);
                Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            }),

            ("a decision API that never answers times out", async () =>
            {
                using var silent = new TcpListener(IPAddress.Loopback, 0);
                silent.Start();
                var silentUrl = new Uri($"http://127.0.0.1:{((IPEndPoint)silent.LocalEndpoint).Port}");
                await using var app = await StartAppAsync(o =>
                {
                    Configure(o, silentUrl);
                    o.Timeout = TimeSpan.FromMilliseconds(100);
                });
                var watch = Stopwatch.StartNew();
                using var response = await SendAsync(app, HttpMethod.Get, "/", BrowserUa);
                Equal(HttpStatusCode.OK, response.StatusCode);
                True(watch.Elapsed < TimeSpan.FromSeconds(3), $"took {watch.Elapsed}");
            }),

            ("bad options fail at startup", async () =>
            {
                var error = await ThrowsAsync<OptionsValidationException>(
                    () => StartAppAsync(o => o.Url = sidecar.Url)); // token missing
                True(error.Message.Contains("Token"), error.Message);

                error = await ThrowsAsync<OptionsValidationException>(() => StartAppAsync(o => o.Token = Sidecar.Token));
                True(error.Message.Contains("Url"), error.Message);

                var builder = WebApplication.CreateBuilder();
                await using var bare = builder.Build();
                var missing = Throws<InvalidOperationException>(() => bare.UseSentryCove());
                True(missing.Message.Contains("AddSentryCove"), missing.Message);
            }),
        };

        var failed = 0;
        foreach (var (name, run) in tests)
        {
            try
            {
                await run();
                Console.WriteLine($"PASS  {name}");
            }
            catch (Exception ex)
            {
                failed++;
                Console.WriteLine($"FAIL  {name}\n      {ex.GetType().Name}: {ex.Message}");
            }
        }

        Console.WriteLine($"\n{tests.Length - failed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;
    }

    private static void Configure(SentryCoveOptions options, Uri url)
    {
        options.Url = url;
        options.Token = Sidecar.Token;
    }

    private static async Task<TestApp> StartAppAsync(Action<SentryCoveOptions> configure)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Services.AddSentryCove(configure);

        var app = builder.Build();
        app.UseSentryCove();
        app.MapGet("/", (HttpContext context) => context.GetSentryCoveAgent()?.Label ?? "middleware did not run");
        app.MapPost("/contact", () => "received");
        app.MapPost("/login", () => Results.Unauthorized());
        app.MapGet("/.env", () => "SECRET=should-never-be-served");
        try
        {
            await app.StartAsync();
        }
        catch
        {
            await app.DisposeAsync();
            throw;
        }

        return new TestApp(app, new Uri(app.Urls.First()));
    }

    private static async Task<HttpResponseMessage> SendAsync(TestApp app, HttpMethod method, string path, string userAgent)
    {
        using var request = new HttpRequestMessage(method, new Uri(app.Address, path));
        request.Headers.TryAddWithoutValidation("User-Agent", userAgent);
        return await Http.SendAsync(request);
    }

    /// <summary>Send a hand-written request line (HttpClient cannot send absolute-form targets).</summary>
    private static async Task<int> RawStatusAsync(Uri address, string requestLine)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(address.Host, address.Port);
        await using var stream = tcp.GetStream();
        var request = $"{requestLine}\r\nHost: {address.Authority}\r\nUser-Agent: {BrowserUa}\r\nConnection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request));
        using var reader = new StreamReader(stream, Encoding.ASCII);
        var statusLine = await reader.ReadLineAsync() ?? throw new IOException("no response");
        return int.Parse(statusLine.Split(' ')[1]);
    }

    private static void Equal<T>(T expected, T actual, string? context = null)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"expected <{expected}> but got <{actual}>{(context is null ? "" : $" ({context})")}");
        }
    }

    private static void True(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static async Task<TException> ThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException ex)
        {
            return ex;
        }

        throw new InvalidOperationException($"expected {typeof(TException).Name} but nothing was thrown");
    }

    private static TException Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException ex)
        {
            return ex;
        }

        throw new InvalidOperationException($"expected {typeof(TException).Name} but nothing was thrown");
    }

    private sealed record TestApp(WebApplication App, Uri Address) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await App.StopAsync();
            await App.DisposeAsync();
        }
    }
}
