using System.Text.Json;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Plugins;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Jellyfin.Plugin.PlexAuth;

public sealed class ServiceRegistrator : IPluginServiceRegistrator
{
    public void RegisterServices(IServiceCollection services, IServerApplicationHost applicationHost)
    {
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<LoginFlows>();
        services.AddSingleton<LoginRateGate>();
        services.TryAddSingleton(_ => new PlexClient(new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(10) }));
        services.AddSingleton<Accounts>();
        services.AddSingleton<IAuthenticationProvider, PlexOnlyAuthenticationProvider>();
        services.AddHostedService<EntitlementWorker>();
        services.AddTransient<IStartupFilter, StartupFilter>();
    }
}

public sealed class StartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.UseMiddleware<PluginMiddleware>();
        next(app);
    };
}

public sealed class PluginMiddleware(RequestDelegate next, IApplicationPaths paths, Accounts accounts)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if (HttpMethods.IsPost(context.Request.Method) && context.Request.Path.Equals(new PathString("/Users/AuthenticateByName")))
        {
            context.Request.EnableBuffering(32768, 32768);
            try
            {
                using var json = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: context.RequestAborted);
                var username = json.RootElement.EnumerateObject().FirstOrDefault(property => property.Name.Equals("Username", StringComparison.OrdinalIgnoreCase)).Value;
                if (username.ValueKind == JsonValueKind.String && await accounts.IsManagedUsernameAsync(username.GetString()!))
                {
                    context.Response.StatusCode = 401;
                    return;
                }
            }
            catch (Exception exception) when (exception is JsonException or IOException)
            {
                context.Response.StatusCode = 400;
                return;
            }
            finally { context.Request.Body.Position = 0; }
        }
        var path = context.Request.Path.Value?.TrimEnd('/');
        if (Plugin.Settings.Enabled && (HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method))
            && (path == "/web" || path == "/web/index.html"))
        {
            var file = Path.Combine(paths.WebPath, "index.html");
            if (File.Exists(file))
            {
                var html = await File.ReadAllTextAsync(file, context.RequestAborted);
                var basePath = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(context.Request.PathBase.Value ?? "");
                html = html.Replace("</body>", $"<script src=\"{basePath}/plexauth/assets/auth.js\" defer></script></body>", StringComparison.OrdinalIgnoreCase);
                context.Response.ContentType = "text/html; charset=utf-8";
                context.Response.Headers.CacheControl = "no-store";
                if (!HttpMethods.IsHead(context.Request.Method)) await context.Response.WriteAsync(html, context.RequestAborted);
                return;
            }
        }
        await next(context);
    }
}