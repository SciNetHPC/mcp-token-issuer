# Contributing

Thanks for your interest. This project is maintained by SciNet HPC Consortium
and is used in production, so changes are reviewed conservatively.

## Start with an issue

Open an issue before writing code. Describe the problem, the deployment it
affects, and what you propose. That avoids a large pull request that cannot be
merged for policy or compatibility reasons.

## Pull requests

Pull requests are welcome and are reviewed by the maintainers. Merge rights
stay with SciNet; being a consumer of the software does not imply write
access. The maintainers decide whether, when, and in what form a change lands.

A pull request should:

- be focused on one problem,
- include tests for behaviour changes,
- keep `npm run check`, `npm test`, and `npm run build` green,
- preserve the existing configuration surface unless the change is discussed
  first — other deployments pin a release and rely on it,
- avoid site-specific values. Hostnames, directory DNs, group names, and
  service lists belong in configuration, not in code.

## Development

```sh
npm ci
npm run check
npm test
npm run dev     # http://localhost:5000
```

Node.js 24 or newer is required.

Tests use the built-in `node:test` runner through `tsx`. They do not need a
directory or an IdP. If you add a rule or a token-format change, add a test at
the same level as the existing ones.

## Commit messages

Use the imperative mood and a short subject line, for example:

```
Reject tokens whose svc does not match the server
```

Explain the reason in the body when it is not obvious. Reference the issue if
there is one.

## Secrets

Never commit credentials, tokens, private keys, or a populated `.env`. The
repository is scanned for secrets in CI, and GitHub push protection should be
enabled on the repository. If you find a committed secret, report it privately
as described in [SECURITY.md](SECURITY.md) rather than opening an issue.

## Licence of contributions

By submitting a pull request you agree that your contribution is licensed
under the MIT licence used by this project (inbound = outbound). Do not submit
code you cannot license that way.

## Language

The user interface is bilingual (English and French). Code comments and
documentation are in English. If you change user-visible text, update both
languages or note that the French string is pending translation.
