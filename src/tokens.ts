import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { config } from "./config";
import { log } from "./log";

// Token format (shared with the file-mcp server; see README):
//
//   fmcpv1.<base64url(payload)>.<base64url(hmac)>
//
//   payload = {"sub","svc","iat","exp","jti"}
//   hmac    = HMAC-SHA256(secret, "fmcpv1:" + payload)
//
// In production the issuer and the MCP servers share TOKEN_HMAC_SECRET via
// Vault; the servers verify the signature and that `svc` matches their own
// service id.

export const TOKEN_VERSION = "fmcpv1";

export type TokenClaims = {
    sub: string;
    svc: string;
    iat: number;
    exp: number;
    jti: string;
    // Optional group memberships (Alliance UserInfo groups), stamped at
    // mint time so the MCP servers' staff exception works for public
    // fmcpv1 tokens too.  The HMAC covers the whole payload, so it is
    // unforgeable; verifiers ignore it when absent (backward compatible).
    groups?: string[];
    // Optional human-readable label chosen by the user at mint time.  It
    // rides inside the HMAC-covered payload (like `groups`) so it cannot
    // be altered; MCP servers ignore it.  Display-only on the issuer side.
    name?: string;
};

export type IssuedToken = TokenClaims & { token: string };

type Store = {
    issued: Record<string, TokenClaims>;
    revokedJtis: string[];
    // Usernames blocked from the service (lowercase).  This is the effective
    // list the MCP servers mirror: the union of the manual blacklist and the
    // automatic account-disable block.  Keeping the union here preserves the
    // existing server contract.
    blacklisted: string[];
    // Ops/abuse blacklist, changed only through the admin API.  Restoring an
    // account never removes this.
    manualBlacklisted: string[];
    // Automatic block driven by `x-scinet-account-enabled=FALSE`.  Removed
    // when the directory says the account is active again.
    autoBlacklisted: string[];
};

type PersistedStore = {
    issued?: Record<string, TokenClaims>;
    revokedJtis?: unknown;
    blacklisted?: unknown;
    manualBlacklisted?: unknown;
    autoBlacklisted?: unknown;
};

function b64u(input: Buffer | string): string {
    return Buffer.from(input).toString("base64url");
}

function mac(payload: string): string {
    return createHmac("sha256", config.token.hmacSecret)
        .update(`${TOKEN_VERSION}:${payload}`)
        .digest("base64url");
}

export function signToken(claims: Omit<TokenClaims, "iat" | "exp" | "jti"> & { iat?: number; exp?: number; jti?: string }): TokenClaims & { token: string } {
    const full: TokenClaims = {
        sub: claims.sub,
        svc: claims.svc,
        iat: claims.iat ?? Math.floor(Date.now() / 1000),
        exp: claims.exp ?? Math.floor(Date.now() / 1000) + config.token.ttlDays * 86400,
        jti: claims.jti ?? randomBytes(16).toString("hex"),
        groups: claims.groups,
        name: claims.name,
    };
    const payload = b64u(JSON.stringify(full));
    return { ...full, token: `${TOKEN_VERSION}.${payload}.${mac(payload)}` };
}

export function verifyToken(token: string, serviceId: string): TokenClaims | null {
    const parts = token.split(".");
    if (parts.length !== 3 || parts[0] !== TOKEN_VERSION) return null;

    const [, payload, signature] = parts;
    const expected = mac(payload);
    const expectedBuf = Buffer.from(expected);
    const gotBuf = Buffer.from(signature);
    if (gotBuf.length !== expectedBuf.length || !timingSafeEqual(gotBuf, expectedBuf)) {
        return null;
    }

    let claims: TokenClaims;
    try {
        claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    } catch {
        return null;
    }
    if (!claims || claims.svc !== serviceId) return null;
    if (claims.exp <= Math.floor(Date.now() / 1000) - 5 * 60) return null; // 5 min leeway
    return claims;
}

// ---------------------------------------------------------------- store --

let store: Store = {
    issued: {},
    revokedJtis: [],
    blacklisted: [],
    manualBlacklisted: [],
    autoBlacklisted: [],
};
let storeDirty = false;
let persistTimer: NodeJS.Timeout | null = null;

function normUser(sub: string): string {
    return sub.trim().toLowerCase();
}

function normUsers(value: unknown): string[] | undefined {
    if (!Array.isArray(value)) return undefined;
    return [...new Set(
        value
            .filter((item): item is string => typeof item === "string")
            .map(normUser)
            .filter(Boolean),
    )];
}

function recomputeBlacklisted(): void {
    store.blacklisted = [...new Set([...store.manualBlacklisted, ...store.autoBlacklisted])];
}

// Read lazily so tests and restart-controlled deploys can override it.
function storePath(): string {
    return process.env.TOKEN_STORE_PATH || config.token.storePath;
}

async function loadStore(): Promise<void> {
    try {
        const raw = await fs.readFile(storePath(), "utf8");
        const parsed = JSON.parse(raw) as PersistedStore;
        const effective = normUsers(parsed.blacklisted) ?? [];
        const storedManual = normUsers(parsed.manualBlacklisted);
        const auto = normUsers(parsed.autoBlacklisted) ?? [];
        // Stores written before the split only have `blacklisted`; those
        // entries were all manual.  A partially migrated store may already
        // have `autoBlacklisted`; keep anything in the effective list that is
        // not auto as manual so no existing block is lost.
        const manual = storedManual ?? effective.filter((sub) => !auto.includes(sub));
        store = {
            issued: parsed.issued ?? {},
            revokedJtis: normUsers(parsed.revokedJtis) ?? [],
            manualBlacklisted: manual,
            autoBlacklisted: auto,
            blacklisted: [],
        };
        recomputeBlacklisted();
    } catch {
        store = {
            issued: {},
            revokedJtis: [],
            blacklisted: [],
            manualBlacklisted: [],
            autoBlacklisted: [],
        };
    }
}

async function writeStore(): Promise<void> {
    if (!storeDirty) return;
    storeDirty = false;
    const path_ = storePath();
    const tmp = `${path_}.tmp`;
    try {
        await fs.mkdir(path.dirname(path_), { recursive: true });
        await fs.writeFile(tmp, JSON.stringify(store, null, 2));
        await fs.rename(tmp, path_);
    } catch (e) {
        // Leave the store dirty so the next mutation or flush retries, and log
        // rather than letting an unhandled rejection terminate the process.
        storeDirty = true;
        log.warn("token store write failed", {
            error: e instanceof Error ? e.message : String(e),
        });
        throw e;
    }
}

function scheduleWrite(delayMs: number): void {
    if (persistTimer) return;
    persistTimer = setTimeout(() => {
        persistTimer = null;
        void writeStore().catch(() => {
            // writeStore already logged.  Retry slowly so a transient failure
            // does not spin, and so the on-disk store eventually catches up.
            scheduleWrite(5000);
        });
    }, delayMs);
}

/**
 * Write any pending state immediately.  Tests use this so their temporary
 * directories can be removed deterministically; a graceful shutdown can use it
 * for the same reason.
 */
export async function flushStore(): Promise<void> {
    if (persistTimer) {
        clearTimeout(persistTimer);
        persistTimer = null;
    }
    await writeStore();
}

function persist(): void {
    storeDirty = true;
    scheduleWrite(200);
}

export async function initStore(): Promise<void> {
    await loadStore();
    const now = Math.floor(Date.now() / 1000);
    const expired = Object.keys(store.issued)
        .filter((jti) => store.issued[jti].exp <= now);
    if (expired.length > 0) {
        for (const jti of expired) delete store.issued[jti];
        persist();
    }
}

export function issueToken(
    sub: string,
    serviceId: string,
    ttlDays: number,
    opts: { groups?: string[]; name?: string } = {},
): IssuedToken {
    if (isBlacklisted(sub)) {
        throw new Error(`user ${normUser(sub)} is blacklisted`);
    }
    const capped = Math.max(1, Math.min(ttlDays, config.token.maxTtlDays));
    const iat = Math.floor(Date.now() / 1000);
    const claims = signToken({
        sub,
        svc: serviceId,
        iat,
        exp: iat + capped * 86400,
        groups: opts.groups,
        name: opts.name,
    });
    const issued = {
        sub: claims.sub,
        svc: claims.svc,
        iat: claims.iat,
        exp: claims.exp,
        jti: claims.jti,
        groups: claims.groups,
        name: claims.name,
    };
    store.issued[claims.jti] = issued;
    persist();
    return { ...issued, token: claims.token };
}

export function listIssued(sub: string): TokenClaims[] {
    const now = Math.floor(Date.now() / 1000);
    return Object.values(store.issued)
        .filter((c) => c.sub === sub && c.exp > now)
        .sort((a, b) => b.iat - a.iat);
}

export function revoke(jti: string, sub: string): boolean {
    const claims = store.issued[jti];
    if (!claims || claims.sub !== sub) return false;
    if (!store.revokedJtis.includes(jti)) {
        store.revokedJtis.push(jti);
    }
    delete store.issued[jti];
    persist();
    return true;
}

export function isRevoked(jti: string): boolean {
    return store.revokedJtis.includes(jti);
}

// ------------------------------------------------------ admin & blacklist --

export function isBlacklisted(sub: string): boolean {
    return store.blacklisted.includes(normUser(sub));
}

export function listBlacklisted(): string[] {
    return [...store.blacklisted];
}

/** True only for the ops/abuse blacklist, not an automatic disable block. */
export function isManualBlacklisted(sub: string): boolean {
    return store.manualBlacklisted.includes(normUser(sub));
}

/** True only for the automatic account-disable block. */
export function isAutoBlacklisted(sub: string): boolean {
    return store.autoBlacklisted.includes(normUser(sub));
}

export function listManualBlacklisted(): string[] {
    return [...store.manualBlacklisted];
}

export function listAutoBlacklisted(): string[] {
    return [...store.autoBlacklisted];
}

/** Revoke a token by jti regardless of owner (admin path). */
export function adminRevoke(jti: string): boolean {
    const claims = store.issued[jti];
    if (!claims) return false;
    if (!store.revokedJtis.includes(jti)) {
        store.revokedJtis.push(jti);
    }
    delete store.issued[jti];
    persist();
    return true;
}

/** Revoke every currently-issued token belonging to *sub*. */
export function revokeAllFor(sub: string): string[] {
    const key = normUser(sub);
    const jtis = Object.values(store.issued)
        .filter((c) => normUser(c.sub) === key)
        .map((c) => c.jti);
    for (const jti of jtis) {
        if (!store.revokedJtis.includes(jti)) {
            store.revokedJtis.push(jti);
        }
        delete store.issued[jti];
    }
    if (jtis.length > 0) persist();
    return jtis;
}

/** Block *sub* manually and revoke all their current tokens. */
export function blacklistUser(sub: string): { added: boolean; revoked: string[] } {
    const key = normUser(sub);
    const added = !store.manualBlacklisted.includes(key);
    const revoked = revokeAllFor(key);
    if (added) {
        store.manualBlacklisted.push(key);
        recomputeBlacklisted();
        persist();
    }
    return { added, revoked };
}

/** Remove the manual blacklist entry.  An automatic disable block remains. */
export function unblacklistUser(sub: string): boolean {
    const key = normUser(sub);
    const idx = store.manualBlacklisted.indexOf(key);
    if (idx < 0) return false;
    store.manualBlacklisted.splice(idx, 1);
    recomputeBlacklisted();
    persist();
    return true;
}

/**
 * Apply the automatic account-disable block: revoke all current tokens and
 * block new issuance.  Idempotent; calling it again still catches tokens
 * minted between sweep runs.
 */
export function autoBlacklistUser(sub: string): { added: boolean; revoked: string[] } {
    const key = normUser(sub);
    const added = !store.autoBlacklisted.includes(key);
    const revoked = revokeAllFor(key);
    if (added) {
        store.autoBlacklisted.push(key);
        recomputeBlacklisted();
        persist();
    }
    return { added, revoked };
}

/** Remove the automatic disable block; the manual blacklist is untouched. */
export function autoUnblacklistUser(sub: string): boolean {
    const key = normUser(sub);
    const idx = store.autoBlacklisted.indexOf(key);
    if (idx < 0) return false;
    store.autoBlacklisted.splice(idx, 1);
    recomputeBlacklisted();
    persist();
    return true;
}

/** Every user with at least one currently-issued token (for admin search). */
export function listUsers(): string[] {
    const users = new Set<string>();
    for (const c of Object.values(store.issued)) users.add(c.sub);
    return [...users].sort((a, b) => a.localeCompare(b));
}
