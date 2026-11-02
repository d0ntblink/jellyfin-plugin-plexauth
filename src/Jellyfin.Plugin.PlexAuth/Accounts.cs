using System.Security;
using System.Text.Json;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Users;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.PlexAuth;

public sealed record AccountLink(long PlexId, Guid UserId, string Username, string PlexUsername, string ProtectedToken, DateTimeOffset LastVerified, string? AvatarUrl = null);

public sealed class Accounts
{
    private readonly IUserManager _users;
    private readonly ISessionManager _sessions;
    private readonly INetworkManager _network;
    private readonly IDataProtector _protector;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly string _file;
    private readonly Dictionary<long, AccountLink> _links;
    private readonly PlexClient _plex;
    private readonly IProviderManager _images;
    private readonly ILogger<Accounts> _logger;

    public Accounts(IUserManager users, ISessionManager sessions, INetworkManager network, IApplicationPaths paths, PlexClient plex, IProviderManager images, ILogger<Accounts> logger)
    {
        _users = users;
        _sessions = sessions;
        _network = network;
        _plex = plex;
        _images = images;
        _logger = logger;
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
                var username = PreferredUsername(identity, name => _users.GetUserByName(name) is not null);
                user = await _users.CreateUserAsync(username);
                await _users.ChangePassword(user.Id, LoginFlows.Secret());
                await _users.UpdatePolicyAsync(user.Id, NewPolicy(Plugin.Settings.LibraryIds, user.PasswordResetProviderId));
            }
            CheckPolicy(user, remoteIp);
            user = await SyncUsernameAsync(user, identity.Username, identity.Id);
            var avatarUrl = await SyncAvatarAsync(user, identity, existing?.AvatarUrl);
            _links[identity.Id] = new AccountLink(identity.Id, user.Id, user.Username, identity.Username, _protector.Protect(token), DateTimeOffset.UtcNow, avatarUrl);
            await SaveAsync();
            return user;
        }
        finally { _lock.Release(); }
    }

    public static string PreferredUsername(PlexIdentity identity, Func<string, bool> unavailable)
    {
        var preferred = identity.Username.Trim();
        var fallback = "plex-" + identity.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (preferred.Length is > 0 and <= 64 && !preferred.Any(char.IsControl)
            && preferred.IndexOfAny(['/', '\\', ':', '<', '>', '|', '"']) < 0 && !unavailable(preferred)) return preferred;
        if (!unavailable(fallback)) return fallback;
        throw new SecurityException("The Plex profile name conflicts with an existing Jellyfin account.");
    }

    private async Task<User> SyncUsernameAsync(User user, string plexUsername, long plexId)
    {
        if (user.HasPermission(PermissionKind.IsAdministrator)) throw new SecurityException("Cannot modify an administrator profile.");
        var desired = PreferredUsername(new PlexIdentity(plexId, plexUsername, false), name =>
        {
            var existing = _users.GetUserByName(name);
            return existing is not null && existing.Id != user.Id;
        });
        if (user.Username != desired)
        {
            await _users.RenameUser(user.Id, user.Username, desired);
            return _users.GetUserById(user.Id) ?? throw new SecurityException("The linked Jellyfin account no longer exists.");
        }
        return user;
    }

    private async Task<string?> SyncAvatarAsync(User user, PlexIdentity identity, string? previousUrl)
    {
        if (string.IsNullOrEmpty(identity.Thumb) || (identity.Thumb == previousUrl && user.ProfileImage is not null)) return previousUrl;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var avatar = await _plex.AvatarAsync(identity, timeout.Token);
            if (avatar is null) return previousUrl;
            var directory = Path.Combine(Path.GetDirectoryName(_file)!, "avatars", user.Id.ToString("N"));
            Directory.CreateDirectory(directory);
            var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(avatar.Bytes));
            var file = Path.Combine(directory, hash + avatar.Extension);
            using var stream = new MemoryStream(avatar.Bytes);
            await _images.SaveImage(stream, avatar.ContentType, file);
            user.ProfileImage = new ImageInfo(file);
            await _users.UpdateUserAsync(user);
            return identity.Thumb;
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or OperationCanceledException or ArgumentException)
        {
            _logger.LogWarning("Plex avatar could not be synchronized; the existing profile image was preserved.");
            return previousUrl;
        }
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

    public async Task VerifiedAsync(AccountLink link, PlexIdentity identity)
    {
        await _lock.WaitAsync();
        try
        {
            if (_links.TryGetValue(link.PlexId, out var current) && current.ProtectedToken == link.ProtectedToken)
            {
                var user = _users.GetUserById(current.UserId) ?? throw new SecurityException("The linked Jellyfin account no longer exists.");
                user = await SyncUsernameAsync(user, identity.Username, link.PlexId);
                var avatarUrl = await SyncAvatarAsync(user, identity, current.AvatarUrl);
                _links[link.PlexId] = current with { LastVerified = DateTimeOffset.UtcNow, PlexUsername = identity.Username, Username = user.Username, AvatarUrl = avatarUrl };
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
                await accounts.VerifiedAsync(link, identity);
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