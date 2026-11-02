namespace Jellyfin.Plugin.PlexAuth;

public sealed class LoginRateGate(TimeProvider clock)
{
    private readonly object _lock = new();
    private readonly Dictionary<string, (DateTimeOffset Until, int Count)> _requests = [];

    public bool TryEnter(string key, int limit)
    {
        lock (_lock)
        {
            var now = clock.GetUtcNow();
            foreach (var expired in _requests.Where(pair => pair.Value.Until <= now).Select(pair => pair.Key).ToArray()) _requests.Remove(expired);
            if (!_requests.TryGetValue(key, out var current))
            {
                if (_requests.Count >= 1024) return false;
                current = (now.AddMinutes(1), 0);
            }
            if (current.Count >= limit) return false;
            _requests[key] = (current.Until, current.Count + 1);
            return true;
        }
    }
}