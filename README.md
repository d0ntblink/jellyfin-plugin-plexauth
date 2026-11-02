# Jellyfin Plex Auth

Experimental Plex-account login plugin for Jellyfin 12.x. Tested against an
isolated Jellyfin **12.4.0** server with a test-only Plex responder, not yet
certified against a real Plex account or physical mobile clients.

## Login

- Jellyfin Web: a **Login with Plex** button uses Plex's documented PIN flow,
  then receives a normal Jellyfin session. Installed web files are not edited.
- Native apps: choose **Quick Connect** in Finamp/Jellyfin, open
  `/plexauth/connect`, enter the app's code, and approve **Login with Plex**.
  The app receives its own normal Jellyfin token; it does not use browser cookies
  for playback. A browser is used only for Plex approval.
- This plugin cannot add a new login button inside an unmodified native app.
  Finamp's active redesign branch implements Quick Connect; verify the feature
  in the actual installed app version before deployment.

## Access Policy

An authenticated Plex account must see the **exact configured Plex machine ID**
in its resources. A server-name match or membership of some other Plex server
is insufficient. Identities map by numeric Plex ID to a stable Jellyfin UUID.
The visible username and profile photo are imported from Plex on login and
entitlement refresh. Existing numeric-name accounts are renamed in place,
preserving their UUID, sessions, permissions and watched data. An invalid or
occupied Plex username falls back to `plex-<numeric-account-id>`; an existing
local account is never claimed. Local accounts, including the administrator,
are never automatically matched by username/email, linked, or demoted.

Avatars use bounded HTTPS downloads from approved Plex/Gravatar hosts and
Jellyfin's native image provider. Failed imports preserve the existing image.
Jellyfin has no corresponding profile-email field, and Plex passwords are never
copied. The profile's password form is not a request for your Plex password;
managed accounts continue to authenticate only through Plex/Quick Connect.

**Any qualifying Plex-server access grants all configured Jellyfin library IDs.**
This is intentional, not a mirror of Plex's individual library/age/label shares.
Only explicitly configured Jellyfin libraries are granted, not future libraries.
Restricted Plex identities and managed Home profiles are not supported.
No administrator, Live TV management, public-sharing, or content-deletion rights
are granted. Plugin-managed accounts cannot use Jellyfin password login.

Entitlements are rechecked approximately once a minute. A confirmed denial
revokes the managed user's Jellyfin device tokens, including Quick Connect
tokens. Plex outages permit existing tokens a 15-minute grace period measured
from the last successful check; new logins fail closed. This is not an instant
stream cutoff or a guarantee that already-downloaded media becomes inaccessible.

## Build And Configure

Requires .NET 10 SDK. Build:

```sh
dotnet build src/Jellyfin.Plugin.PlexAuth/Jellyfin.Plugin.PlexAuth.csproj -c Release
```

Copy **only** the production `Jellyfin.Plugin.PlexAuth.dll` from the Release
output and the production `meta.json` into `PlexAuth_0.1.1.0` under Jellyfin's actual plugin directory, then
restart **Jellyfin only**. Never install the test-provider assembly. In
Dashboard > Plugins > Plex Auth, configure the exact HTTPS URL, Plex machine
identifier, and selected Jellyfin library UUIDs. The plugin is disabled by default.
Use `/Library/VirtualFolders` with an administrator session to identify library
UUIDs. Keep the existing independent local admin and NAS recovery access.

Plex tokens are protected with ASP.NET Data Protection under
`<Jellyfin data>/plexauth`; mappings use numeric Plex IDs and Jellyfin UUIDs.
Protect and back up that entire directory, including its private key material.
Encryption at rest does not protect against an attacker who can read both the
token store and its keys. Tokens/passwords are not returned to the client or
logged by the plugin. Normal Jellyfin session tokens remain in the native client.

## Tests

```sh
dotnet test tests/PlexAuth.Tests/PlexAuth.Tests.csproj
npm ci
npx playwright install chromium
dotnet build tests/PlexAuth.TestProvider/PlexAuth.TestProvider.csproj
```

The integration harness requires Node 24, OpenSSL, FFmpeg, Chromium's OS dependencies,
and the official Jellyfin 12.4 application directory at
`$PLEXAUTH_TEST_DIR/server`. It creates a fresh, loopback-only profile and local
test certificate, simulates only Plex responses, and stops the server on exit.
Run `node tests/integration.mjs`. See the CI workflow for a reproducible runtime
copy from the pinned image. Do not point the harness at production configuration.

Verified: 23 unit/security tests plus genuine Jellyfin plugin loading, native
Quick Connect token issuance, selected-library policy, CSRF/replay/password
denial, entitlement revocation, local-admin preservation, browser login/button,
mobile layout, image rendering, in-place profile rename/avatar import with
unchanged UUID/permissions/app token. Physical app playback, real Plex approval,
and watched-state synchronization remain unverified.

## Watched State And Rollout

Watched-state synchronization is deliberately separate. The maintained
[JellyPlex-Watched](https://github.com/luigi311/JellyPlex-Watched) project is the
candidate for movies/TV progress and completion. It is not installed or enabled
by this plugin. Music and literal bidirectional unwatched resets are not covered.
See [the plan](docs/plan.md) for matching, dry-run, permission, and rollback gates.

## Research

- [Plex's official authentication guidance](https://forums.plex.tv/t/authenticating-with-plex/609370)
- [Plex Media Server API](https://developer.plex.tv/pms/)
- [Seerr account/server authorization](https://github.com/seerr-team/seerr/blob/develop/server/api/plextv.ts)
- [Tautulli Plex user login](https://github.com/Tautulli/Tautulli/blob/master/plexpy/webauth.py)
- [Official Jellyfin plugin template](https://github.com/jellyfin/jellyfin-plugin-template)
- [Jellyfin 12 SSO implementation](https://github.com/lolerskatez/jellyfin-plugin-sso)
- [Jellyfin Quick Connect](https://jellyfin.org/docs/general/server/quick-connect/)

The implementation uses the existing Jellyfin APIs and reference integration
patterns, not an OIDC/LDAP identity server. Licensed under GPL-3.0-only; see LICENSE.