using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Jellyfin.Plugin.PlexAuth;

public sealed class PluginConfiguration : BasePluginConfiguration
{
    public bool Enabled { get; set; }
    public string PublicUrl { get; set; } = string.Empty;
    public string MachineId { get; set; } = string.Empty;
    public string ClientIdentifier { get; set; } = Guid.NewGuid().ToString("N");
    public Guid[] LibraryIds { get; set; } = [];

    public void Validate()
    {
        if (!Enabled || string.IsNullOrWhiteSpace(MachineId) || string.IsNullOrWhiteSpace(ClientIdentifier)
            || LibraryIds.Length == 0 || LibraryIds.Length > 256 || LibraryIds.Any(identifier => identifier == Guid.Empty)
            || LibraryIds.Distinct().Count() != LibraryIds.Length
            || !Uri.TryCreate(PublicUrl, UriKind.Absolute, out var uri) || uri.Scheme != "https"
            || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new System.Security.SecurityException("Plex login is disabled or not configured safely.");
    }
}

public sealed class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    public Plugin(IApplicationPaths paths, IXmlSerializer serializer) : base(paths, serializer) { Instance = this; }
    public static Plugin? Instance { get; private set; }
    public override string Name => "Plex Auth";
    public override Guid Id => Guid.Parse("679e3ea6-3b13-4ebf-8b60-e8eab13e9ecd");
    public IEnumerable<PluginPageInfo> GetPages() => [new() { Name = Name, EmbeddedResourcePath = "Jellyfin.Plugin.PlexAuth.Web.config.html" }];
    public static PluginConfiguration Settings => Instance?.Configuration ?? throw new InvalidOperationException("Plugin is not loaded.");
}