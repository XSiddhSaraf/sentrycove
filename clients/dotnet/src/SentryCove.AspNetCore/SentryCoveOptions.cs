namespace SentryCove.AspNetCore;

/// <summary>Settings for the SentryCove middleware.</summary>
public sealed class SentryCoveOptions
{
    internal const int MinTokenLength = 16;

    /// <summary>Base URL of the SentryCove decision API, for example <c>http://127.0.0.1:8787</c>.</summary>
    public Uri? Url { get; set; }

    /// <summary>The shared secret the decision API was started with (<c>SENTRYCOVE_API_TOKEN</c>).</summary>
    public string? Token { get; set; }

    /// <summary>How long to wait for a decision. Default: 500 ms.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// What to do when the decision API cannot be reached or returns an error.
    /// <c>true</c> (default) lets the request through, so SentryCove can never take the app down;
    /// <c>false</c> answers 503.
    /// </summary>
    public bool FailOpen { get; set; } = true;

    internal string? Validate()
    {
        if (Url is null || !Url.IsAbsoluteUri || (Url.Scheme != Uri.UriSchemeHttp && Url.Scheme != Uri.UriSchemeHttps))
        {
            return "SentryCove: Url must be the http(s) URL of the decision API, for example http://127.0.0.1:8787.";
        }

        if (string.IsNullOrEmpty(Token) || Token.Length < MinTokenLength)
        {
            return $"SentryCove: Token must be the decision API secret (at least {MinTokenLength} characters).";
        }

        if (Timeout <= TimeSpan.Zero)
        {
            return "SentryCove: Timeout must be positive.";
        }

        return null;
    }
}
