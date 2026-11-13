# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting on this repository
(**Security → Advisories → Report a vulnerability**). If that is unavailable,
contact the SciNet HPC Consortium maintainers through
<https://www.scinethpc.ca/> and ask for the security contact.

Include:

- the affected version or commit,
- what an attacker can do and what they need to start,
- a reproduction or a precise description of the path,
- any suggested fix.

We will acknowledge receipt, investigate, and coordinate disclosure with you.
Please give us a reasonable window before publishing details.

## Supported versions

Only the latest tagged release is supported. There are no long-term support
branches. Fixes are issued as a new tag; deployments are expected to pin a
tag and upgrade deliberately.

## Scope

In scope:

- token forgery or acceptance of a token for the wrong service,
- authentication or session-handling flaws,
- authorization bypass in the admin API or the service filter,
- revocation or blacklist bypass,
- injection through directory lookups or the JSON store,
- secret disclosure through logs or error responses.

Out of scope:

- findings that require control of the OIDC provider or the directory,
- denial of service through unbounded traffic (put a proxy in front),
- the behaviour of MCP servers that consume these tokens; report those to
  their own projects.

## Deployment expectations

The issuer is one part of a trust boundary. A safe deployment:

- terminates TLS and sets `NODE_ENV=production`, so session cookies are
  `Secure`;
- keeps `SESSION_SECRET`, `TOKEN_HMAC_SECRET`, and the OIDC client secret in a
  secret manager, not in the repository or the image;
- serves the token store on a volume that only the issuer can write and the
  consuming MCP servers can read;
- rotates `TOKEN_HMAC_SECRET` by issuing a new deployment and re-minting
  tokens, because rotation invalidates every existing token;
- runs the container as a non-root user with a read-only root filesystem where
  the runtime permits it.

## Known design properties

These are intentional, not vulnerabilities:

- **Tokens are deployment-scoped.** They are HMAC-signed with the local
  secret. A token from another site is not valid here, and vice versa.
- **Sign-out is local.** It clears the application session but not the IdP
  session.
- **Directory failures fail closed for gated services.** An LDAP error hides
  cluster-gated services but does not revoke existing non-cluster tokens.
- **The admin list is a file on a shared volume.** Anyone who can write that
  file can grant admin access; protect the volume accordingly.
