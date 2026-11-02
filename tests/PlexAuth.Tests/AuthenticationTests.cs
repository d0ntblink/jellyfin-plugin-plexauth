using System.Net;
using System.Security;
using Jellyfin.Plugin.PlexAuth;
using Xunit;

namespace PlexAuth.Tests;

public sealed class AuthenticationTests
{
    [Theory]
    [InlineData("server-id", "server", true)]
    [InlineData("other-id", "server", false)]
    [InlineData("server-id", "player", false)]
    [InlineData("server-id", "notserver", false)]
    [InlineData("server-id", "player,server", true)]
    public async Task AccessRequiresExactServerIdentity(string identifier, string provides, bool allowed)
    {
        using var http = new HttpClient(new FakePlex($$"""[{"clientIdentifier":"{{identifier}}","provides":"{{provides}}","name":"My Plex"}]"""));
        var client = new PlexClient(http);
        if (allowed) Assert.Equal(123, (await client.AuthorizeAsync("private-test-token", "client", "server-id", default)).Id);
        else await Assert.ThrowsAsync<SecurityException>(() => client.AuthorizeAsync("private-test-token", "client", "server-id", default));
    }

    [Theory]
    [InlineData("{\"id\":0,\"username\":\"admin\"}")]
    [InlineData("{\"id\":123,\"username\":\"\"}")]
    [InlineData("{\"id\":123,\"username\":\"child\",\"restricted\":true}")]
    public async Task InvalidAndRestrictedIdentitiesAreDenied(string identity)
    {
        using var http = new HttpClient(new FakePlex("[]", identity));
        await Assert.ThrowsAsync<SecurityException>(() => new PlexClient(http).AuthorizeAsync("private-test-token", "client", "server-id", default));
    }

    [Fact]
    public void FlowsRequireCorrectProofAndAreSingleUse()
    {
        var flows = new LoginFlows(TimeProvider.System);
        var state = flows.Add(new PlexPin(1, "code", null, DateTimeOffset.UtcNow.AddMinutes(3)), "proof", "ABC123");
        Assert.Null(flows.Consume(state, "wrong"));
        Assert.Equal("ABC123", flows.Consume(state, "proof")!.QuickConnectCode);
        Assert.Null(flows.Consume(state, "proof"));
    }

    [Fact]
    public void ExpiredFlowsCannotAuthorize()
    {
        var flows = new LoginFlows(TimeProvider.System);
        var state = flows.Add(new PlexPin(1, "code", null, DateTimeOffset.UtcNow.AddMinutes(-1)), "proof", null);
        Assert.Null(flows.Read(state, "proof"));
    }

    [Fact]
    public void NewUsersReceiveOnlySelectedLibrariesAndNoAdministrativeRights()
    {
        var libraries = Enumerable.Range(0, 5).Select(_ => Guid.NewGuid()).ToArray();
        var policy = Accounts.NewPolicy(libraries, "native-reset-provider");
        Assert.False(policy.IsAdministrator);
        Assert.False(policy.EnableAllFolders);
        Assert.Equal(libraries, policy.EnabledFolders);
        Assert.False(policy.EnableContentDeletion);
        Assert.False(policy.EnableLiveTvManagement);
        Assert.Contains(nameof(PlexOnlyAuthenticationProvider), policy.AuthenticationProviderId);
        Assert.Equal("native-reset-provider", policy.PasswordResetProviderId);
    }

    [Fact]
    public async Task PlexPasswordsCannotAuthenticateManagedAccounts()
    {
        await Assert.ThrowsAsync<MediaBrowser.Controller.Authentication.AuthenticationException>(() => new PlexOnlyAuthenticationProvider().Authenticate("plex-123", "not-a-plex-password"));
    }

    [Fact]
    public void LoginAttemptsAreBounded()
    {
        var gate = new LoginRateGate(TimeProvider.System);
        for (var attempt = 0; attempt < 5; attempt++) Assert.True(gate.TryEnter("client", 5));
        Assert.False(gate.TryEnter("client", 5));
        Assert.True(gate.TryEnter("other-client", 5));
    }

    private sealed class FakePlex(string resources, string identity = "{\"id\":123,\"username\":\"alice\"}") : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal("plex.tv", request.RequestUri!.Host);
            Assert.Equal("https", request.RequestUri.Scheme);
            Assert.True(request.Headers.Contains("X-Plex-Token"));
            var body = request.RequestUri.AbsolutePath.EndsWith("/user", StringComparison.Ordinal) ? identity : resources;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") });
        }
    }
}