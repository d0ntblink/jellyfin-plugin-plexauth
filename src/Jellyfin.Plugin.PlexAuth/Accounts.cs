using System.Security;
using System.Text.Json;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Users;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.PlexAuth;

public sealed record AccountLink(long PlexId, Guid UserId, string Username, string PlexUsername, string ProtectedToken, DateTimeOffset LastVerified);

public sealed class Accounts
{
    private readonly IUserManager _users;
    private readonly ISessionManager _sessions;
    private readonly INetworkManager _network;
    private readonly IDataProtector _protector;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly string _file;
    private readonly Dictionary<long, AccountLink> _links;

    public Accounts(IUserManager users, ISessionManager sessions, INetworkManager network, IApplicationPaths paths)
    {
        _users = users;
        _sessions = sessions;
        _network = network;
        var directory = Path.Combine(paths.DataPath, "plexauth");
        Directory.CreateDirectory(directory);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        _protector = DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(directory, "keys")), builder => builder.SetApplicationName("Jellyfin.PlexAuth"))
            .CreateProtector("PlexTokens.v1");
        _file = Path.Combine(directory, "accounts.json");
        _links = File.Exists(_file)
            ? JsonSerializer.Deserialize<Dictionary<long, AccountLink>>(File.ReadAllText(_file)) ?? throw new SecurityException("Account mapping is invalid.")
            : [];
    }

    public async Task<User> ResolveAsync(PlexIdentity identity, string token, string remoteIp)
    {
        Plugin.Settings.Validate();
        await _lock.WaitAsync();
        try
        {
            User user;
            if (_links.TryGetValue(identity.Id, out var existing))
                user = _users.GetUserById(existing.UserId) ?? throw new SecurityException("The linked Jellyfin account no longer exists.");
            else
            {
                var username = "plex-" + identity.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
                if (_users.GetUserByName(username) is not null) throw new SecurityException("The reserved Jellyfin account name is already in use.");
                user = await _users.CreateUserAsync(username);
                await _users.ChangePassword(user.Id, LoginFlows.Secret());
                await _users.UpdatePolicyAsync(user.Id, NewPolicy(Plugin.Settings.LibraryIds, user.PasswordResetProviderId));
            }
            CheckPolicy(user, remoteIp);
            _links[identity.Id] = new AccountLink(identity.Id, user.Id, user.Username, identity.Username, _protector.Protect(token), DateTimeOffset.UtcNow);
            await SaveAsync();
            return user;
        }
        finally { _lock.Release(); }
    }

    public static UserPolicy NewPolicy(Guid[] libraries, string passwordResetProviderId) => new()
    {
        IsAdministrator = false,
        IsHidden = true,
        EnableAllFolders = false,
        EnabledFolders = libraries.ToArray(),
        EnableLiveTvAccess = false,
        EnableLiveTvManagement = false,
        EnableAllChannels = false,
        EnableContentDeletion = false,
        EnableContentDownloading = true,
        EnablePublicSharing = false,
        EnableRemoteControlOfOtherUsers = false,
        EnableSharedDeviceControl = false,
        AuthenticationProviderId = typeof(PlexOnlyAuthenticationProvider).FullName!,
        PasswordResetProviderId = passwordResetProviderId
    };

    public void CheckPolicy(User user, string remoteIp)
    {
        if (user.HasPermission(PermissionKind.IsAdministrator) || user.HasPermission(PermissionKind.IsDisabled)
            || (!user.HasPermission(PermissionKind.EnableRemoteAccess) && !_network.IsInLocalNetwork(remoteIp))
            || !user.IsParentalScheduleAllowed())
            throw new SecurityException("This Jellyfin account cannot sign in.");
    }

    public async Task<IReadOnlyList<AccountLink>> SnapshotAsync()
    {
        await _lock.WaitAsync();
        try { return _links.Values.ToArray(); }
        finally { _lock.Release(); }
    }

    public string Token(AccountLink link) => _protector.Unprotect(link.ProtectedToken);

    public async Task<bool> IsManagedUsernameAsync(string username)
    {
        var user = _users.GetUserByName(username);
        if (user is null) return false;
        await _lock.WaitAsync();
        try { return _links.Values.Any(link => link.UserId == user.Id) || user.AuthenticationProviderId == typeof(PlexOnlyAuthenticationProvider).FullName; }
        finally { _lock.Release(); }
    }

    public async Task VerifiedAsync(AccountLink link, string plexUsername)
    {
        await _lock.WaitAsync();
        try
        {
            if (_links.TryGetValue(link.PlexId, out var current) && current.ProtectedToken == link.ProtectedToken)
            {
                _links[link.PlexId] = current with { LastVerified = DateTimeOffset.UtcNow, PlexUsername = plexUsername };
                await SaveAsync();
            }
        }
        finally { _lock.Release(); }
    }

    public async Task RevokeAsync(AccountLink link)
    {
        await _lock.WaitAsync();
        try
        {
            if (_links.TryGetValue(link.PlexId, out var current) && current.ProtectedToken == link.ProtectedToken && current.LastVerified == link.LastVerified)
                await _sessions.RevokeUserTokens(link.UserId, string.Empty);
        }
        finally { _lock.Release(); }
    }

    private async Task SaveAsync()
    {
        var temporary = _file + "." + Guid.NewGuid().ToString("N") + ".tmp";
        await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(_links));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(temporary, _file, true);
    }
}

public sealed class PlexOnlyAuthenticationProvider : IAuthenticationProvider
{
    public string Name => "Plex Auth (Quick Connect)";
    public bool IsEnabled => true;
    public Task<ProviderAuthenticationResult> Authenticate(string username, string password) => throw new AuthenticationException("Use Plex login or Quick Connect.");
    public Task ChangePassword(User user, string newPassword) => throw new AuthenticationException("Plex-managed accounts do not use Jellyfin passwords.");
}

public sealed class EntitlementWorker(Accounts accounts, PlexClient plex, ILogger<EntitlementWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception)
            {
                logger.LogError("Plex entitlement maintenance failed; access will be checked on the next pass.");
            }
            if (!await timer.WaitForNextTickAsync(stoppingToken)) return;
        }
    }

    public async Task CheckOnceAsync(CancellationToken cancellationToken)
    {
        foreach (var link in await accounts.SnapshotAsync())
        {
            try
            {
                Plugin.Settings.Validate();
                var identity = await plex.AuthorizeAsync(accounts.Token(link), Plugin.Settings.ClientIdentifier, Plugin.Settings.MachineId, cancellationToken);
                if (identity.Id != link.PlexId) throw new SecurityException("Plex identity changed.");
                await accounts.VerifiedAsync(link, identity.Username);
            }
            catch (PlexUnavailableException)
            {
                if (DateTimeOffset.UtcNow - link.LastVerified >= TimeSpan.FromMinutes(15)) await accounts.RevokeAsync(link);
                logger.LogWarning("Plex entitlement check unavailable; existing access has a bounded grace period.");
            }
            catch (Exception exception) when (exception is SecurityException or System.Security.Cryptography.CryptographicException)
            {
                await accounts.RevokeAsync(link);
                logger.LogInformation("Revoked a Plex-managed account's Jellyfin device tokens.");
            }
        }
    }
}