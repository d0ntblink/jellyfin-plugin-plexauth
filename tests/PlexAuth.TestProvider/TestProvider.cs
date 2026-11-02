using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Jellyfin.Plugin.PlexAuth;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace PlexAuth.TestProvider;

public sealed class TestPlugin : BasePlugin<BasePluginConfiguration>
{
    public TestPlugin(IApplicationPaths paths, IXmlSerializer serializer) : base(paths, serializer) { }
    public override string Name => "Plex Auth Isolated Test Provider";
    public override Guid Id => Guid.Parse("074e8582-44e1-47fa-aa17-d9e8c3fdafba");
}

public sealed class TestRegistrator : IPluginServiceRegistrator
{
    public void RegisterServices(IServiceCollection services, IServerApplicationHost applicationHost)
    {
        if (Environment.GetEnvironmentVariable("PLEXAUTH_ISOLATED_TEST") != "yes") throw new InvalidOperationException("This provider is for isolated tests only.");
        services.RemoveAll<PlexClient>();
        services.AddSingleton(new PlexClient(new HttpClient(new FakePlex())));
    }
}

public sealed class FakePlex : HttpMessageHandler
{
    public static bool Allowed { get; set; } = true;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;
        object payload = path.EndsWith("/user", StringComparison.Ordinal)
            ? new { id = 123, username = "isolated-alice", restricted = false }
            : path.EndsWith("/resources", StringComparison.Ordinal)
                ? Allowed ? new[] { new { clientIdentifier = "isolated-server", provides = "server" } } : []
                : new { id = 1, code = "isolated-pin", authToken = path.EndsWith("/pins", StringComparison.Ordinal) ? null : "isolated-plex-token", expiresAt = DateTimeOffset.UtcNow.AddMinutes(5) };
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json") });
    }
}

[ApiController, AllowAnonymous, Route("_plexauth-test")]
public sealed class TestController(IEnumerable<IHostedService> hostedServices) : ControllerBase
{
    [HttpPost("revoke")]
    public async Task<IActionResult> Revoke(CancellationToken cancellationToken)
    {
        var expected = Environment.GetEnvironmentVariable("PLEXAUTH_TEST_CONTROL");
        var supplied = Request.Headers["X-Test-Control"].ToString();
        if (string.IsNullOrWhiteSpace(expected) || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected)), SHA256.HashData(Encoding.UTF8.GetBytes(supplied)))) return Unauthorized();
        FakePlex.Allowed = false;
        await hostedServices.OfType<EntitlementWorker>().Single().CheckOnceAsync(cancellationToken);
        return Ok(new { revoked = true });
    }
}