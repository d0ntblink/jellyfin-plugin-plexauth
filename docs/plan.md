# Implementation And Rollout Plan

## Chosen Architecture

One Jellyfin server plugin owns Plex authentication, exact-server entitlement,
dedicated non-admin users, web login, and native Quick Connect approval. No
AuthPortal, Postgres, LDAP, reverse-proxy authentication, or separate identity
service is required. Normal Jellyfin library/playback permissions and device
tokens remain authoritative.

AuthPortal was evaluated, not deployed: its Plex authorization method returns
success for cached `media_access=true` without refreshing Plex, and its resource
matcher accepts a server-name fallback even when a machine ID is configured.
Its OIDC output also needs a separate Jellyfin SSO consumer. The narrower
blacktirion Plex OIDC bridge explicitly handles authentication, not authorization.
No maintained direct Plex-login Jellyfin plugin satisfying the requested native
client policy was identified in the bounded repository search.

## Security And Reliability

- Plex credentials are entered at Plex, not in Jellyfin or the plugin. PINs have
  a bounded lifetime; only the originating approval browser can exchange a flow.
  That browser binding protects the short-lived approval transaction, not the
  native app's ongoing session. Native apps hold ordinary Jellyfin device tokens.
- Same-origin POST checks, fixed HTTPS Plex endpoints, disabled redirects,
  bounded responses, anonymous request limits, and single-use state restrict
  cross-site login, SSRF, polling abuse, and replay.
- Numeric Plex identity plus native Jellyfin UUID prevents username/email
  takeover. New user names do not claim existing accounts. Existing admin status
  is never imported from Plex. Password denial checks actual plugin ownership.
- A successful server-membership check grants the declared libraries. The
  operator explicitly chose all five sources for qualifying users, rather than
  per-Plex-library sharing. Do not market this as parental-control parity.
- Poll-based revocation has latency. A generation check prevents a stale result
  from revoking a newly refreshed identity. Cloud/API failures are distinguished
  from confirmed access denial. The local admin remains independent of Plex.
- Token/key storage is private, atomic JSON plus Data Protection; no direct
  Jellyfin/Plex database writes are used. A corrupt mapping/key directory is a
  stop/recovery condition, not permission to recreate or relink accounts.
- This is a single-instance experimental plugin, not security-certified software.
  In-memory login state is lost on restart. Third-party plugin code runs inside
  Jellyfin, so installation must have an independent recovery lane.

## Watched-State Integration

Reuse JellyPlex-Watched, initially pinned to a reviewed revision. Before any
writes, verify its authentication headers against Jellyfin 12.4 and run a
single-pass dry run scoped to one explicitly mapped test identity and library.
Never use broad automatic same-name matching for the operator's first pass.

Build explicit mappings from the plugin's stored Plex username/numeric ID and
Jellyfin username/UUID, without exporting its protected tokens or key material.
Supply the sync service's own privileged credentials through private secret
storage. Keep eligibility and sync scopes aligned so a revoked Plex user is not
silently included by a separately running history job. The current app caches
configuration; mapping changes require a controlled config refresh/restart.

Matching uses provider IDs and/or media filenames after Jellyfin has indexed
the intended sources. Empty/missing indexes are not proof of successful sync.
No forced scan is part of plugin deployment. Missing or ambiguous matches must
be skipped and reported, never guessed across users or UHD/non-UHD libraries.

Movies/TV completion and resume progress fit the existing engine. It does not
support music. Its merge prefers more-complete states; exact bidirectional
"mark unwatched" propagation requires a separate decision/investigation.
Choose one-way versus bidirectional writes with the operator before enabling
them. Archive the affected user/item state and verify an exact restoration path
for the initial bounded write test. Do not mutate real viewing history merely
to prove connectivity.

## Live Trial Gate

Local implementation and isolated tests are approved. The operator subsequently
approved production installation and one Jellyfin-only restart, and explicitly
waived backups. Real Plex account approval and watched-state writes have not
been performed by the installer.

1. Inspect current Jellyfin container identity/start time, exact plugin paths,
   selected library IDs, local admin access, active sessions and disk ownership.
   Record Plex's identity/start time solely as a continuity baseline.
2. Verify the independent NAS SSH lane and local-admin recovery. Save private
   affected-file/container preimages; review the exact production package and
   proposed plugin configuration, including its five UUIDs and disabled default.
3. Obtain approval for one Jellyfin-only install/restart and bounded login trial.
   Do not recreate Plex, restart Docker/NAS, change GPU settings, open ingress,
   enable sync writes, or start a full media scan.
4. Install only the production assembly. Verify healthy startup and unchanged
   local admin/Plex before enabling the reviewed Plex configuration.
5. Complete real Plex approval with the operator; verify a new non-admin account,
   web login and physical Finamp/Jellyfin Quick Connect. Test an unauthorized
   account/revocation only with a deliberately scoped test identity, not by
   removing the operator's production Plex share or invalidating owner tokens.
6. Roll back on failed startup, admin access, unexpected permissions or unknown
   results. Disable the plugin/revoke only managed tokens, restore the exact
   affected plugin/config files and restart only Jellyfin. If its UI is down,
   use NAS SSH to remove/quarantine only this plugin assembly and restart it.
   Retain media and profile data; do not delete existing users or restore an
   entire live database over unrelated changes. Reconcile any partially created
   account by its saved UUID/ownership, never by username alone.

## Acceptance Recorded

The isolated server is the actual 12.4.0 runtime copied read-only from the
production application's binary directory, with a fresh local profile and no
production configuration/media. Test-only Plex fixtures never ship in the
production package. A native Finamp-labelled Quick Connect request receives a
real Jellyfin token, then becomes unauthorized after the fixture revokes Plex
access. A separate local admin (including a `plex-` prefix) remains authorized.
Playwright verifies the web button/browser credential handoff and mobile page,
including loaded images. This is API/browser testing, not physical app or real
Plex-provider certification.

## Live Installation Recorded

Installed and enabled on 2026-11-02 without backups, as explicitly requested.
The production DLL and versioned manifest were published atomically; only
Jellyfin was restarted. After startup, HTTPS health, disabled-first plugin load,
local administrator login, exact Plex machine ID and all five library IDs were
verified before enabling login. Plex's container identity/start time remained
unchanged. A fresh browser verified the live Login with Plex button and mobile
Quick Connect form. No sync service, watched-history write or full scan was started.

Jellyfin rewrites descriptive/default manifest metadata during loading. The
installer preserves exact DLL SHA-256 verification and compares manifest GUID,
name, version, ABI, owner, active status and assembly whitelist structurally.
Use `scripts/live.mjs verify` for the matching built/installed version; do not repeat
`install` or restart it from stale context. Removing only the persistent plugin
directory is part of rollback: replacing the Docker image alone would reload it.
Physical app login/playback and real Plex-provider approval remain unverified.

## Profile Sync Update

Version 0.1.1 imports Plex username and available profile photo. The identity
mapping remains numeric Plex ID to native Jellyfin UUID; existing numeric-name
accounts are renamed in place. Name collisions never claim local accounts.
Images use approved HTTPS hosts, a two-MiB response bound, no forwarded Plex
token and Jellyfin's native image provider. Missing or failed photos preserve
the existing image. Plex passwords and email are not copied into Jellyfin.

The operator approved publication and a no-backup, Jellyfin-only upgrade after
23 focused tests and a real isolated migration test preserved UUID, library
policy and an existing native app token while serving the imported avatar.
The updater's `upgrade` phase accepts only the known 0.1.0 manifest/DLL hash,
refuses active playback or an existing target, publishes a versioned package,
and restarts only Jellyfin. Existing configuration and account mappings stay
outside the package and are not overwritten. Confirm actual live results before
claiming the profile update has completed.