namespace SentryCove.AspNetCore;

/// <summary>Who SentryCove thinks is making the request.</summary>
/// <param name="Kind">
/// <c>verified</c> (cryptographically proven AI agent), <c>declared</c> (User-Agent names a known bot;
/// a claim, not proof), <c>automation</c> (HTTP library or headless browser) or <c>unclassified</c>.
/// </param>
/// <param name="Name">Agent name when known, for example <c>GPTBot</c>.</param>
/// <param name="Label"><c>kind</c> or <c>kind:name</c>, convenient for logs.</param>
public sealed record AgentIdentity(string Kind, string? Name, string Label)
{
    /// <summary>The identity used when no classification is available.</summary>
    public static AgentIdentity Unclassified { get; } = new("unclassified", null, "unclassified");

    /// <summary>True when the caller proved its identity with a valid Web Bot Auth signature.</summary>
    public bool IsVerified => Kind == "verified";
}
