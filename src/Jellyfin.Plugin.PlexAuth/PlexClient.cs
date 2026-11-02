using System.Net;
using System.Net.Http.Json;
using System.Security;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Jellyfin.Plugin.PlexAuth;

public sealed record PlexPin(long Id, string Code, string? AuthToken, DateTimeOffset ExpiresAt);
public sealed record PlexIdentity(long Id, string Username, bool Restricted);
public sealed record PlexResource(string ClientIdentifier, string Provides);

public sealed class PlexUnavailableException : Exception
{
    public PlexUnavailableException() : base("Plex authentication is temporarily unavailable.") { }
}

public sealed class PlexClient(HttpClient http)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<PlexPin> CreatePinAsync(string clientId, CancellationToken cancellationToken)
    {
        using var request = Request(HttpMethod.Post, "pins", clientId);
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["strong"] = "true" });
        var pin = await ReadAsync<PlexPin>(request, cancellationToken);
        if (pin.Id <= 0 || string.IsNullOrWhiteSpace(pin.Code) || pin.ExpiresAt <= DateTimeOffset.UtcNow)
            throw new SecurityException("Plex returned an invalid login challenge.");
        return pin;
    }

    public Task<PlexPin> PollPinAsync(PlexPin pin, string clientId, CancellationToken cancellationToken)
    {
        return ReadOwnedRequestAsync<PlexPin>(Request(HttpMethod.Get, $"pins/{pin.Id}?code={Uri.EscapeDataString(pin.Code)}", clientId), cancellationToken);
    }

    public async Task<PlexIdentity> AuthorizeAsync(string token, string clientId, string machineId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(machineId) || string.IsNullOrWhiteSpace(token))
            throw new SecurityException("Plex server authorization is not configured.");
        var identity = await ReadOwnedRequestAsync<PlexIdentity>(Request(HttpMethod.Get, "user", clientId, token), cancellationToken);
        if (identity.Id <= 0 || string.IsNullOrWhiteSpace(identity.Username) || identity.Restricted)
            throw new SecurityException("This Plex identity is not supported or is restricted.");
        var resources = await ReadOwnedRequestAsync<List<PlexResource>>(Request(HttpMethod.Get, "resources?includeHttps=1", clientId, token), cancellationToken);
        if (!resources.Any(resource => resource is not null && resource.ClientIdentifier == machineId
            && !string.IsNullOrWhiteSpace(resource.Provides)
            && resource.Provides.Split(',').Any(value => value.Trim() == "server")))
            throw new SecurityException("This Plex account does not have access to the configured server.");
        return identity;
    }

    private static HttpRequestMessage Request(HttpMethod method, string endpoint, string clientId, string? token = null)
    {
        var request = new HttpRequestMessage(method, "https://plex.tv/api/v2/" + endpoint);
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.Add("X-Plex-Product", "Jellyfin Plex Auth");
        request.Headers.Add("X-Plex-Version", "0.1.0");
        request.Headers.Add("X-Plex-Client-Identifier", clientId);
        if (token is not null) request.Headers.Add("X-Plex-Token", token);
        return request;
    }

    private async Task<TValue> ReadOwnedRequestAsync<TValue>(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using (request) return await ReadAsync<TValue>(request, cancellationToken);
    }

    private async Task<TValue> ReadAsync<TValue>(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden or HttpStatusCode.NotFound)
                throw new SecurityException("Plex rejected the login or authorization challenge.");
            if (!response.IsSuccessStatusCode) throw new PlexUnavailableException();
            await response.Content.LoadIntoBufferAsync(1024 * 1024, cancellationToken);
            return await response.Content.ReadFromJsonAsync<TValue>(Json, cancellationToken)
                ?? throw new SecurityException("Plex returned an empty authentication response.");
        }
        catch (JsonException) { throw new SecurityException("Plex returned an invalid authentication response."); }
        catch (HttpRequestException) { throw new PlexUnavailableException(); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new PlexUnavailableException(); }
    }
}