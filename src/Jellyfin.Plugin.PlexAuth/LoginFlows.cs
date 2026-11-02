using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;

namespace Jellyfin.Plugin.PlexAuth;

public sealed record LoginFlow(PlexPin Pin, string BrowserProof, string? QuickConnectCode, DateTimeOffset Deadline);

public sealed class LoginFlows(TimeProvider clock)
{
    private readonly ConcurrentDictionary<string, LoginFlow> _flows = new();

    public string Add(PlexPin pin, string browserProof, string? quickConnectCode)
    {
        foreach (var pair in _flows.Where(pair => pair.Value.Deadline <= clock.GetUtcNow())) _flows.TryRemove(pair.Key, out _);
        if (_flows.Count >= 128) throw new InvalidOperationException("Too many pending login requests.");
        var state = Secret();
        var deadline = pin.ExpiresAt < clock.GetUtcNow().AddMinutes(5) ? pin.ExpiresAt : clock.GetUtcNow().AddMinutes(5);
        _flows[state] = new LoginFlow(pin, browserProof, quickConnectCode, deadline);
        return state;
    }

    public LoginFlow? Read(string state, string browserProof)
    {
        if (state.Length > 128 || !_flows.TryGetValue(state, out var flow) || flow.Deadline <= clock.GetUtcNow()) return null;
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(flow.BrowserProof)),
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(browserProof))) ? flow : null;
    }

    public LoginFlow? Consume(string state, string browserProof)
    {
        return Read(state, browserProof) is not null && _flows.TryRemove(state, out var flow) ? flow : null;
    }

    public static string Secret() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
}