# token-issuer

Self-service API-token issuer for [MCP](https://modelcontextprotocol.io/)
servers.

A user signs in through an OIDC provider, chooses an MCP server, and is issued
an HMAC-signed API token bound to their username and to that server. The token
can be pasted into any MCP-capable client. There is no per-client registration
and no administrator involvement after the OIDC client is set up.

The software was written and is maintained by **SciNet HPC Consortium** for the
MCP servers it operates. It is published so that other Alliance sites — and
anyone else with a compatible OIDC provider and directory — can run their own
instance.

**Each deployment is independent.** Tokens are signed with that deployment's
`TOKEN_HMAC_SECRET` and are only accepted by MCP servers configured with the
same secret. A token minted at one site does not work at another.

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Token format](#token-format)
- [Token verification](#token-verification)
- [Configuration](#configuration)
- [Services](#services)
- [Cluster-gated services](#cluster-gated-services)
- [Account disable and revocation](#account-disable-and-revocation)
- [Sign-in behaviour](#sign-in-behaviour)
- [Administration](#administration)
- [Development](#development)
- [Deployment](#deployment)
- [Security](#security)
- [Contributing](#contributing)
- [Licence](#licence)

## Requirements

- Node.js 24 or newer. The container image in this repository uses 24.22.3.
- An OIDC provider with a confidential client. The issuer reads `sub` and
  `preferred_username`; `locale` is used to seed the UI language. Group or
  entitlement claims are optional.
- Optional: an LDAPS directory. It is only consulted when the configured
  service list contains a cluster-gated entry.

There is no database. State is a single JSON file at `TOKEN_STORE_PATH`.

## Quick start

```sh
cp .env.example .env      # fill in the OIDC client and the two secrets
npm ci
npm run dev               # http://localhost:5000
```

For a real login, the redirect URI must be registered at the IdP and the app
must be reachable at that origin during the flow. A loopback URI is usually
enough for local development; an SSH port forward works if the provider will
not accept one.

Build and run the bundled output:

```sh
npm run build
npm start
```

## How it works

1. The browser authenticates through OIDC. The issuer keeps a server-side
   session; it does not store IdP tokens.
2. If the service list contains cluster-gated entries, the session's username
   is looked up in the directory to decide which services to show.
3. `POST /api/tokens` re-checks the same rules before minting, so a crafted
   request cannot obtain a service the UI would have hidden.
4. Issued tokens and revocations are persisted in `TOKEN_STORE_PATH`. MCP
   servers mount that file read-only and reload it on a short poll.
5. A background sweep rechecks users who hold live tokens against the
   directory, so an explicitly disabled account loses its tokens without an
   administrator acting.

The HTTP surface is small: static pages, `/login`, `/auth/callback`,
`/logout`, `/api/session`, `/api/services`, `/api/tokens`, and the admin
endpoints listed below.

## Token format

A token is a self-contained, versioned, HMAC-signed string:

```
fmcpv1.<base64url(payload)>.<base64url(hmac)>
```

where:

```
payload = {"sub":"<username>","svc":"<service id>","iat":<unix>,"exp":<unix>,"jti":"<32 hex>"}
hmac    = HMAC-SHA256(TOKEN_HMAC_SECRET, "fmcpv1:" + payload)
```

Two optional claims may also appear, both HMAC-covered and therefore
unforgeable:

- `groups` — a staff marker derived from the IdP's `ccServiceAccess` claim
  (`cc_staff`/`co_staff` are folded into `cc-staff`; see `src/groups.ts`).
  This is an Alliance convention; other deployments can ignore it.
- `name` — a user-chosen display label for the token.

`svc` binds a token to exactly one MCP server: a token minted for `docs` is
rejected by `jobs`.

## Token verification

A server recomputes the MAC and checks:

1. the signature is valid (constant-time compare);
2. `exp` is not in the past;
3. `svc` equals the server's own service id;
4. `jti` is not on the shared revocation list (`revokedJtis` in the store);
5. `sub` is not on the effective block list (`blacklisted` in the store —
   the union of manual entries and automatic account-disable blocks).

The issuer and every MCP server that accepts its tokens must share the same
`TOKEN_HMAC_SECRET`. Provision it from a secret manager; it is never read from
the repository.

## Configuration

Copy `.env.example` to `.env` for local runs. In production, inject the values
from your secret manager or orchestration layer.

| Variable | Meaning |
|---|---|
| `PORT` | HTTP listen port (default `5000`) |
| `SESSION_SECRET` | express-session signing secret (required) |
| `OIDC_ISSUER_URL` | OIDC issuer, e.g. `https://idp.example.org` |
| `OIDC_CLIENT_ID` | registered confidential client id (required) |
| `OIDC_CLIENT_SECRET` | client secret (required) |
| `OIDC_REDIRECT_URI` | callback URL registered at the IdP (required) |
| `TOKEN_HMAC_SECRET` | HMAC key shared with the MCP servers (required) |
| `TOKEN_STORE_PATH` | JSON file holding issued tokens and revocations (default `./token-store.json`) |
| `TOKEN_TTL_DAYS` | default token lifetime in days (default `30`) |
| `TOKEN_MAX_TTL_DAYS` | maximum lifetime a user may request (default `365`) |
| `SERVICES` | JSON array describing the token dropdown; see [Services](#services) |
| `ADMIN_GROUPS` | comma-separated OIDC groups allowed to use the admin API/UI |
| `ADMIN_LIST_PATH` | ops-maintained admin list, OR-ed with `ADMIN_GROUPS` (default `/data/admin-users.json`; a missing file is empty) |
| `LDAP_URL` | LDAPS URL for directory checks; must be `ldaps://` |
| `LDAP_BASE_DN` | search base (default `dc=computecanada,dc=ca`) |
| `LDAP_BIND_DN` | optional read-only bind DN; anonymous search is used when empty |
| `LDAP_BIND_PASSWORD` | password for `LDAP_BIND_DN`, if set |
| `LDAP_CA_CERTS` | optional CA bundle path, if the directory certificate is not system-trusted |
| `LDAP_TLS_SERVERNAME` | optional TLS SNI name, needed if `LDAP_URL` uses an IP address |
| `LDAP_TIMEOUT_MS` | connect/operation timeout in milliseconds (default `3000`) |
| `LDAP_CACHE_TTL_MS` | per-user access cache lifetime in milliseconds (default `300000`; `0` disables it) |
| `BALAM_GROUP_CN` | POSIX group that grants Balam access (default `lcl_balam`) |
| `ACCOUNT_DISABLE_SWEEP_SECONDS` | how often to recheck users with live tokens (default `60`; `0` disables the sweep) |
| `ACCOUNT_DISABLE_SWEEP_CONCURRENCY` | maximum concurrent directory lookups during the sweep (default `4`) |

The shipped defaults (`ADMIN_GROUPS=scinet`, the service list, the directory
base DN) are SciNet's production configuration. Every one of them is
overridable. A deployment that does not use the Alliance directory should set
`LDAP_BASE_DN`, `ADMIN_GROUPS`, and `SERVICES` explicitly.

## Services

`SERVICES` is a JSON array of objects:

```json
[
  {
    "id": "docs",
    "name": "Docs MCP",
    "description": "Search the documentation.",
    "descriptionFr": "Rechercher dans la documentation.",
    "url": "https://mcp.example.org/docs"
  },
  {
    "id": "files",
    "name": "File MCP",
    "description": "Read your files.",
    "url": "https://mcp.example.org/files",
    "slurmCluster": "trillium"
  }
]
```

| Field | Meaning |
|---|---|
| `id` | Service id embedded in the token as `svc`; must match the MCP server's `SERVICE_ID` |
| `name` | Display name in the dropdown |
| `description` | Shown on the mint page |
| `descriptionFr` | Optional French description, shown when the UI language is French; falls back to `description` |
| `url` | Public MCP endpoint shown to the user |
| `slurmCluster` | Optional; marks the service as cluster-gated (see below) |

When `SERVICES` is unset, the built-in list describes SciNet's production
services. If `SERVICES` is set but is not a JSON array of objects with `id`
and `name`, the issuer falls back to that built-in list rather than starting
with an empty dropdown.

**Hard-wired cluster markers.** For safety, four service ids always carry a
cluster marker even when an operator's `SERVICES` override omits it:
`file-mcp` and `slurm-trillium` (`trillium`), `slurm-trillium-gpu`
(`trillium-gpu`), and `slurm-balam` (`balam`). This prevents an override from
accidentally exposing a cluster service without the directory check. If your
services use different ids, no marker is implied.

## Cluster-gated services

A service with `slurmCluster` set is visible and mintable only when the
directory says the user has access. `GET /api/services` hides it and
`POST /api/tokens` refuses it; a failed or ambiguous directory lookup is
treated as no access.

The rule implementation shipped in `src/accessrules.ts` encodes SciNet's
clusters:

| Service | Rule |
|---|---|
| Trillium | `ccServiceAccess=trillium-access`, or legacy `x-access=trillium` with `x-scinet-account-enabled=TRUE` |
| Trillium-GPU | Same as Trillium; the GPU subcluster inherits the entitlement |
| Balam | `memberUid` in the `BALAM_GROUP_CN` POSIX group **and** current Trillium access |

A person may have both an Alliance `uid` entry and a separate SciNet-local
`cn` entry; entitlements from both are unioned. An explicit
`x-scinet-account-enabled=FALSE` on any entry is a person-level veto and
removes all cluster access, including a separate `ccServiceAccess`
entitlement.

These rules are SciNet-specific. A deployment with a different directory
schema should either leave `slurmCluster` unset — in which case LDAP is not
needed at all — or adapt `src/accessrules.ts` and the attribute names in
`src/ldapaccess.ts`.

If any configured service carries a cluster marker and `LDAP_URL` is unset,
the process refuses to start. This is deliberate: silently hiding a service
looks like a permissions bug. Directory *failures* at request time still hide
the service rather than failing the whole page.

## Account disable and revocation

An explicit `x-scinet-account-enabled=FALSE` in the directory applies an
automatic block: every currently-issued token is revoked and new issuance is
refused, including for non-cluster services. The block is stored separately
from the manual/admin blacklist. When the directory stops reporting the
account as disabled, the automatic block is removed; a manual blacklist is
never cleared by that restore.

Because the directory has no webhook, the issuer checks it:

- at startup and every `ACCOUNT_DISABLE_SWEEP_SECONDS` for users with live
  tokens and users under an automatic block;
- on OIDC login and on `/api/services`;
- before every mint.

Losing Trillium access alone is not an explicit disable: it hides or denies
the cluster services but does not revoke non-cluster tokens. Directory errors
and ambiguous or missing entries are treated as unknown — they neither apply
nor clear a block.

Users can revoke their own tokens from the web UI at any time. Revocation is
immediate locally and reaches the MCP servers on their next store poll.

## Sign-in behaviour

On the first visit in a browser session the issuer makes a passive OIDC
request (`prompt=none`) before showing the page. If an IdP session already
exists, the user is signed in without an extra click. Otherwise the normal
page with the sign-in button is shown.

Sign-out is local to the issuer: it clears the application session but does
not end the IdP session, and it suppresses passive SSO for the rest of that
browser session so signing out does not immediately sign the user back in.

The UI ships in English and French.

## Administration

An admin can revoke anyone's tokens and blacklist a user outright. A
signed-in user is an admin when either:

- their resolved groups intersect `ADMIN_GROUPS`, or
- their username is on the ops-maintained list at `ADMIN_LIST_PATH`, re-read
  on the same short poll as the revocation store.

The IdP used by SciNet releases no `groups` claim, so operator admin access is
normally granted through the list. The file format is:

```json
{"adminUsernames": ["alice", "bob"]}
```

No extra credentials are involved; every admin action is logged against the
session user.

**Admin API** (session-authenticated):

| Method | Path | Effect |
|---|---|---|
| `GET` | `/api/admin/users` | users with at least one live token |
| `GET` | `/api/admin/tokens?sub=<user>` | a user's live tokens |
| `POST` | `/api/admin/tokens/<jti>/revoke` | revoke any token by `jti` |
| `POST` | `/api/admin/users/<sub>/revoke-all` | revoke all of a user's tokens |
| `GET` | `/api/admin/blacklist` | manual blacklist (`users`) and automatic disable blocks (`disabled`) |
| `POST` | `/api/admin/blacklist` `{sub}` | add a manual entry (also revokes all their tokens) |
| `DELETE` | `/api/admin/blacklist?sub=<user>` | remove the manual entry; an automatic block is not admin-removable |

A blocked user cannot mint new tokens (`403`) and has all current tokens
revoked. The store's `blacklisted` field is the union of the manual blacklist
and the automatic block, so MCP servers that mirror it reject circulating
tokens within one poll. Removing a manual entry on an account that is also
automatically disabled returns `409`; the automatic block remains until
access is restored.

## Development

```sh
npm ci
npm run check     # tsc --noEmit
npm test          # node:test suites via tsx
npm run build     # esbuild bundle + static assets into dist/
```

The test suites cover the token format, access rules, group derivation,
account-disable sweep, admin list, and LDAP escaping. They do not require a
directory or an IdP.

## Deployment

This repository contains service code only. Deployment manifests, secrets,
and site-specific runbooks are maintained privately by SciNet.

Any container runtime works. The requirements are:

- TLS termination in front of the service; the session cookie is marked
  `Secure` when `NODE_ENV=production`.
- A persistent volume at `TOKEN_STORE_PATH`, writable by the service user.
- A read-only mount of the same file in each MCP server that accepts these
  tokens, so revocations propagate.
- The same `TOKEN_HMAC_SECRET` in the issuer and those servers.
- Secrets supplied from a secret manager, never baked into an image.

The bundled `Dockerfile` runs as a non-root user and contains no package
manager or downloader in the runtime layer.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues are welcome. Pull requests are
reviewed by the maintainers, who decide whether and when to merge.

## Licence

MIT. See [LICENSE](LICENSE).
