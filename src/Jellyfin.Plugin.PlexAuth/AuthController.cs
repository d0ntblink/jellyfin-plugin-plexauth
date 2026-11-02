using System.Security;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.QuickConnect;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace Jellyfin.Plugin.PlexAuth;

public sealed record StartRequest(string? QuickConnectCode);
public sealed record CompleteRequest(string State, string DeviceId, string? DeviceName);

[ApiController, AllowAnonymous, Route("plexauth")]
public sealed class AuthController(PlexClient plex, LoginFlows flows, Accounts accounts, ISessionManager sessions, IQuickConnect quickConnect, LoginRateGate rate, IApplicationPaths paths) : ControllerBase
{
    private const string Cookie = "__Host-plexauth";

    [HttpGet("login"), HttpGet("connect"), HttpGet("callback")]
    public IActionResult Page()
    {
        var basePath = HtmlEncoder.Default.Encode(Request.PathBase.Value ?? "");
        var icon = Directory.Exists(paths.WebPath) ? Directory.EnumerateFiles(paths.WebPath, "touchicon*.png").Select(Path.GetFileName).FirstOrDefault() : null;
        var logo = icon is null ? string.Empty : $"<img src=\"{basePath}/web/{HtmlEncoder.Default.Encode(icon)}\" alt=\"Jellyfin\" width=\"48\" height=\"48\">";
        Response.Headers.CacheControl = "no-store";
        Response.Headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        return Content($"""
            <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Jellyfin Plex Login</title><link rel="stylesheet" href="{basePath}/plexauth/assets/auth.css"><script src="{basePath}/plexauth/assets/auth.js" defer></script></head>
            <body class="plexauth-standalone"><main id="plexauth-page">{logo}<h1>Login with Plex</h1><form id="plexauth-form"><label for="code">Quick Connect code</label><input id="code" name="code" minlength="6" maxlength="6" autocomplete="off" autocapitalize="characters"><button class="plexauth-button" type="submit"><img class="plexauth-mark" src="{basePath}/plexauth/assets/plex.svg" alt="" width="22" height="22">Login with Plex</button></form><p id="status" role="status"></p><a href="{basePath}/web/index.html#/login">Back to Jellyfin</a></main></body></html>
            """, "text/html; charset=utf-8");
    }

    [HttpGet("assets/{name}")]
    public IActionResult Asset(string name)
    {
        var contentType = name switch { "auth.js" => "text/javascript", "auth.css" => "text/css", "plex.svg" => "image/svg+xml", "OpenSans.ttf" => "font/ttf", "OpenSans-OFL.txt" => "text/plain", _ => null };
        if (contentType is null) return NotFound();
        var stream = typeof(Plugin).Assembly.GetManifestResourceStream("Jellyfin.Plugin.PlexAuth.Web." + name);
        return stream is null ? NotFound() : File(stream, contentType);
    }

    [HttpPost("start")]
    public async Task<IActionResult> Start(StartRequest request, CancellationToken cancellationToken)
    {
        try
        {
            GuardOrigin();
            if (!rate.TryEnter("start:" + HttpContext.Connection.RemoteIpAddress, 5) || !rate.TryEnter("start:global", 30))
                return StatusCode(429, new { error = "Too many login attempts. Try again in a minute." });
            var code = request.QuickConnectCode?.Trim().ToUpperInvariant();
            if (!string.IsNullOrEmpty(code) && (!Regex.IsMatch(code, "^[A-Z0-9]{6}$") || !quickConnect.IsEnabled)) return BadRequest(new { error = "Invalid Quick Connect code or Quick Connect is disabled." });
            var pin = await plex.CreatePinAsync(Plugin.Settings.ClientIdentifier, cancellationToken);
            var proof = LoginFlows.Secret();
            var state = flows.Add(pin, proof, string.IsNullOrEmpty(code) ? null : code);
            Response.Cookies.Append(Cookie, proof, new() { Secure = true, HttpOnly = true, SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax, Path = "/", MaxAge = TimeSpan.FromMinutes(5) });
            Response.Headers.CacheControl = "no-store";
            var callback = Plugin.Settings.PublicUrl.TrimEnd('/') + "/plexauth/callback?state=" + state;
            var url = "https://app.plex.tv/auth#?" + string.Join("&", new Dictionary<string, string>
            {
                ["clientID"] = Plugin.Settings.ClientIdentifier,
                ["code"] = pin.Code,
                ["forwardUrl"] = callback,
                ["context[device][product]"] = "Jellyfin Plex Auth"
            }.Select(pair => Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(pair.Value)));
            return Ok(new { url });
        }
        catch (SecurityException) { return StatusCode(403, new { error = "Plex login is disabled or this request is not allowed." }); }
        catch (PlexUnavailableException) { return StatusCode(503, new { error = "Plex is temporarily unavailable." }); }
        catch (InvalidOperationException) { return StatusCode(429, new { error = "Too many pending login requests." }); }
    }

    [HttpPost("complete")]
    public async Task<IActionResult> Complete(CompleteRequest request, CancellationToken cancellationToken)
    {
        try
        {
            GuardOrigin();
            if (!rate.TryEnter("complete:" + HttpContext.Connection.RemoteIpAddress, 60))
                return StatusCode(429, new { error = "Too many login checks. Try again in a minute." });
            Response.Headers.CacheControl = "no-store";
            var proof = Request.Cookies[Cookie] ?? string.Empty;
            var flow = flows.Read(request.State, proof);
            if (flow is null || string.IsNullOrWhiteSpace(request.DeviceId) || request.DeviceId.Length > 512 || request.DeviceId.Any(char.IsControl)) return BadRequest(new { error = "Login expired or invalid. Start again." });
            var pin = await plex.PollPinAsync(flow.Pin, Plugin.Settings.ClientIdentifier, cancellationToken);
            if (pin.Id != flow.Pin.Id || pin.Code != flow.Pin.Code) throw new SecurityException("Plex login challenge changed.");
            if (string.IsNullOrEmpty(pin.AuthToken)) return StatusCode(202, new { pending = true });
            var identity = await plex.AuthorizeAsync(pin.AuthToken, Plugin.Settings.ClientIdentifier, Plugin.Settings.MachineId, cancellationToken);
            if (flows.Consume(request.State, proof) is null) return BadRequest(new { error = "Login already used." });
            var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
            var user = await accounts.ResolveAsync(identity, pin.AuthToken, remoteIp);
            Response.Cookies.Delete(Cookie, new() { Secure = true, HttpOnly = true, SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax, Path = "/" });
            if (flow.QuickConnectCode is not null)
            {
                var authorized = await quickConnect.AuthorizeRequest(user.Id, flow.QuickConnectCode);
                return authorized ? Ok(new { connected = true }) : BadRequest(new { error = "Quick Connect code expired or was not found." });
            }
            var result = await sessions.AuthenticateDirect(new AuthenticationRequest
            {
                UserId = user.Id, Username = user.Username, App = "Jellyfin Plex Auth", AppVersion = "0.1.2",
                DeviceId = request.DeviceId, DeviceName = (request.DeviceName ?? "Web Browser")[..Math.Min((request.DeviceName ?? "Web Browser").Length, 128)], RemoteEndPoint = remoteIp
            });
            return Ok(result);
        }
        catch (SecurityException) { return StatusCode(403, new { error = "Access denied. Your Plex account must have access to this server and an enabled Jellyfin account." }); }
        catch (PlexUnavailableException) { return StatusCode(503, new { error = "Plex is temporarily unavailable. Try again later." }); }
    }

    private void GuardOrigin()
    {
        Plugin.Settings.Validate();
        var origin = Request.Headers.Origin.ToString();
        if (!string.Equals(origin, new Uri(Plugin.Settings.PublicUrl).GetLeftPart(UriPartial.Authority), StringComparison.Ordinal))
            throw new SecurityException("Cross-origin login is not permitted.");
    }
}