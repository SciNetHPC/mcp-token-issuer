import { Client } from "ldapts";
import { readFileSync } from "node:fs";
import { config } from "./config";
import {
    evaluateClusterAccesses,
    NO_CLUSTER_ACCESS,
    type ClusterAccess,
    type DirectoryAccess,
} from "./accessrules";

// RFC 4515 escaping for the username in an LDAP search filter.  The only
// input here is the OIDC-verified preferred_username, but escaping it still
// prevents filter injection if an IdP ever releases something unexpected.
export function escapeFilterValue(input: string): string {
    let escaped = "";
    for (const ch of input) {
        switch (ch) {
            case "*": escaped += "\\2a"; break;
            case "(": escaped += "\\28"; break;
            case ")": escaped += "\\29"; break;
            case "\\": escaped += "\\5c"; break;
            case "\0": escaped += "\\00"; break;
            default: escaped += ch;
        }
    }
    return escaped;
}

function attribute(entry: Record<string, unknown>, name: string): unknown {
    const key = Object.keys(entry).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
    return key ? entry[key] : undefined;
}

function attributeStrings(entry: Record<string, unknown>, name: string): string[] {
    const value = attribute(entry, name);
    const values = Array.isArray(value) ? value : value === undefined ? [] : [value];
    return values
        .map((item) => {
            if (typeof item === "string") return item;
            if (Buffer.isBuffer(item)) return item.toString("utf8");
            return "";
        })
        .map((item) => item.trim())
        .filter(Boolean);
}

function parseBoolean(value: unknown): boolean | undefined {
    const raw = Array.isArray(value) ? value[0] : value;
    if (typeof raw === "boolean") return raw;
    if (typeof raw !== "string") return undefined;
    if (raw.trim().toLowerCase() === "true") return true;
    if (raw.trim().toLowerCase() === "false") return false;
    return undefined;
}

function toDirectoryAccess(entry: Record<string, unknown>): DirectoryAccess {
    return {
        ccServiceAccess: attributeStrings(entry, "ccServiceAccess"),
        xAccess: attributeStrings(entry, "x-access"),
        enabled: parseBoolean(attribute(entry, "x-scinet-account-enabled")),
    };
}

function newClient(): Client {
    if (!config.ldap.url.toLowerCase().startsWith("ldaps://")) {
        throw new Error("LDAP_URL must use ldaps://");
    }
    let ca: Buffer | undefined;
    if (config.ldap.caPath) {
        ca = readFileSync(config.ldap.caPath);
    }
    // ldapts calls tls.connect(port, host, options) without setting SNI.
    // The directory serves a self-signed default certificate when SNI is
    // absent, even though its normal hostname certificate is valid and
    // system-trusted.  Set servername explicitly (or allow an override when
    // connecting by IP).
    const servername = config.ldap.tlsServername || new URL(config.ldap.url).hostname;
    return new Client({
        url: config.ldap.url,
        timeout: config.ldap.timeoutMs,
        connectTimeout: config.ldap.timeoutMs,
        tlsOptions: {
            servername,
            rejectUnauthorized: true,
            ...(ca ? { ca: [ca] } : {}),
        },
    });
}

// The query deliberately requests only the access attributes and at most two
// entries; an ambiguous result is treated as no access.
async function searchEntries(client: Client, filter: string): Promise<Record<string, unknown>[]> {
    const result = await client.search(config.ldap.baseDn, {
        scope: "sub",
        filter,
        attributes: ["ccServiceAccess", "x-access", "x-scinet-account-enabled"],
        sizeLimit: 2,
        timeLimit: Math.max(1, Math.ceil(config.ldap.timeoutMs / 1000)),
    });
    return result.searchEntries as unknown as Record<string, unknown>[];
}

// Balam entitlement.  The group is a POSIX group found under LDAP_BASE_DN and
// lists members by username in memberUid.  Membership alone is not enough:
// SciNet's sysadmins require current Trillium access too, so a disabled or
// expired account that is still in the group is denied by the Trillium side of
// the intersection.  Other deployments set BALAM_GROUP_CN for their group.
async function searchBalamMembership(client: Client, escapedUsername: string): Promise<boolean> {
    if (!config.balamGroupCn) {
        return false;
    }
    const result = await client.search(config.ldap.baseDn, {
        scope: "sub",
        filter: `(&(objectClass=posixGroup)(cn=${escapeFilterValue(config.balamGroupCn)})(memberUid=${escapedUsername}))`,
        attributes: ["cn"],
        sizeLimit: 2,
        timeLimit: Math.max(1, Math.ceil(config.ldap.timeoutMs / 1000)),
    });
    // The group cn is unique.  An ambiguous result is treated as no
    // membership rather than granting Balam.
    return result.searchEntries.length === 1;
}

type DirectoryLookup = {
    entries: DirectoryAccess[];
    balamMember: boolean;
    // More than one entry matched one of the person lookups.  Treat it as
    // unknown rather than guessing which entry belongs to the user.
    ambiguous: boolean;
};

// Look up a user's directory entries.  Alliance accounts are under
// ou=People,dc=computecanada,dc=ca and use `uid`; SciNet-local accounts are
// under ou=People,dc=scinet,dc=computecanada,dc=ca and use `cn` without
// necessarily carrying a uid.  A person can have both entries, so return both
// and let the access evaluator union them.  Any ambiguous result is treated
// as no access.
async function lookupDirectoryAccessesAndBalam(
    username: string,
    options: { includeBalam?: boolean } = {},
): Promise<DirectoryLookup> {
    if (!config.ldap.enabled) {
        return { entries: [], balamMember: false, ambiguous: false };
    }

    const includeBalam = options.includeBalam ?? true;
    const client = newClient();
    const escaped = escapeFilterValue(username);
    try {
        if (config.ldap.bindDn) {
            if (!config.ldap.bindPassword) {
                throw new Error("LDAP_BIND_DN is set but LDAP_BIND_PASSWORD is empty");
            }
            await client.bind(config.ldap.bindDn, config.ldap.bindPassword);
        }

        const byUid = await searchEntries(client, `(uid=${escaped})`);
        if (byUid.length > 1) {
            return { entries: [], balamMember: false, ambiguous: true };
        }

        const byLocalCn = await searchEntries(
            client,
            `(&(objectClass=x-scinet-local)(cn=${escaped}))`,
        );
        if (byLocalCn.length > 1) {
            return { entries: [], balamMember: false, ambiguous: true };
        }

        const entries: DirectoryAccess[] = [];
        if (byUid.length === 1) {
            entries.push(toDirectoryAccess(byUid[0]));
        }
        if (byLocalCn.length === 1) {
            entries.push(toDirectoryAccess(byLocalCn[0]));
        }

        const balamMember = includeBalam
            ? await searchBalamMembership(client, escaped)
            : false;
        return { entries, balamMember, ambiguous: false };
    } finally {
        try {
            await client.unbind();
        } catch {
            // Ignore unbind errors (e.g. the connection was never established).
        }
    }
}

// Kept as the entry-only helper for tests and callers that do not need Balam.
export async function lookupDirectoryAccesses(username: string): Promise<DirectoryAccess[]> {
    return (await lookupDirectoryAccessesAndBalam(username)).entries;
}

export type AccountState = "disabled" | "active" | "unknown";

/**
 * Pure interpretation of the entries: an explicit FALSE on any entry is a
 * person-level disable.  No entries or an ambiguous result is unknown, not
 * "active", so callers never clear a block based on a failed lookup.
 */
export function accountStateFromEntries(entries: DirectoryAccess[]): AccountState {
    if (entries.length === 0) return "unknown";
    return entries.some((entry) => entry.enabled === false) ? "disabled" : "active";
}

/**
 * Explicit account-disable state, without the access cache.  This deliberately
 * does not treat loss of Trillium as disabled: non-cluster services are still
 * allowed for an expired/non-Trillium account.
 */
export async function accountStateFor(username: string): Promise<AccountState> {
    const trimmed = username.trim();
    if (!trimmed || !config.ldap.enabled) return "unknown";
    const lookup = await lookupDirectoryAccessesAndBalam(trimmed, { includeBalam: false });
    if (lookup.ambiguous) return "unknown";
    return accountStateFromEntries(lookup.entries);
}

type CacheEntry = {
    access: ClusterAccess;
    expiresAt: number;
};

const cache = new Map<string, CacheEntry>();
const inflight = new Map<string, Promise<ClusterAccess>>();

// Per-user access with a short TTL.  Failures are not cached, so an LDAP
// outage is retried on the next request; callers fail closed by hiding the
// Slurm services.  Existing tokens are still checked authoritatively by the
// Slurm server, so this cache only affects mint-time UX.
export async function clusterAccessFor(username: string): Promise<ClusterAccess> {
    const trimmed = username.trim();
    if (!trimmed || !config.ldap.enabled) {
        return NO_CLUSTER_ACCESS;
    }

    const key = trimmed.toLowerCase();
    const now = Date.now();
    const cached = cache.get(key);
    if (cached && cached.expiresAt > now) {
        return cached.access;
    }

    const existing = inflight.get(key);
    if (existing) {
        return existing;
    }

    const task = (async () => {
        const { entries, balamMember } = await lookupDirectoryAccessesAndBalam(trimmed);
        const access = evaluateClusterAccesses(entries, balamMember);
        if (config.ldap.cacheTtlMs > 0) {
            cache.set(key, { access, expiresAt: Date.now() + config.ldap.cacheTtlMs });
        }
        return access;
    })().finally(() => {
        inflight.delete(key);
    });

    inflight.set(key, task);
    return task;
}
