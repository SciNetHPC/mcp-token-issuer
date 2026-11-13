import express, { type NextFunction, type Request, type Response } from "express";
import { config, type Service } from "./config";
import {
    isClusterAllowed,
    NO_CLUSTER_ACCESS,
    type ClusterAccess,
} from "./accessrules";
import { clusterAccessFor } from "./ldapaccess";
import { syncAccountState } from "./disable";
import { log } from "./log";
import {
    buildAuthUrl,
    discardAuthState,
    handleCallback,
    isSilentAuthState,
    type OidcUser,
} from "./oidc";
import { adminList } from "./adminlist";
import {
    adminRevoke,
    blacklistUser,
    isAutoBlacklisted,
    isBlacklisted,
    isManualBlacklisted,
    issueToken,
    listAutoBlacklisted,
    listIssued,
    listManualBlacklisted,
    listUsers,
    revoke,
    revokeAllFor,
    unblacklistUser,
} from "./tokens";

declare module "express-session" {
    interface SessionData {
        user?: OidcUser;
        // UI language, seeded from the OIDC `locale` claim at login and
        // overridable per session via POST /api/language.
        language?: "en" | "fr";
        // True once this browser session has made its one passive SSO
        // attempt, or after an explicit sign-out.  Prevents redirect loops
        // and makes sign-out stick without logging out of the IdP globally.
        silentAttempted?: boolean;
    }
}

// Map an OIDC `locale` claim (e.g. "fr", "fr-CA", "fr_CA") to the UI
// language codes this app understands ("en" | "fr").  Returns undefined
// when locale is missing — the same rule the trillium-chatbot uses.
function mapLocaleToLanguage(locale?: string): "en" | "fr" | undefined {
    if (!locale) return undefined;
    return /^fr(\b|-|_)/i.test(locale) ? "fr" : "en";
}

// When the IdP releases no locale claim, fall back to the browser's
// Accept-Language preference (French gets priority), else English.
function languageFromRequest(req: Request): "en" | "fr" {
    return /(^|,)\s*fr(\b|-|_)/i.test(req.get("Accept-Language") || "") ? "fr" : "en";
}

function requireUser(req: Request, res: Response, next: NextFunction): void {
    if (!req.session.user) {
        res.status(401).json({ error: "not signed in" });
        return;
    }
    next();
}

// Admin = a signed-in user who is either (a) in an ADMIN_GROUPS OIDC group,
// or (b) on the ops-maintained admin list on the shared volume.  The list
// fallback keeps administration working even when the IdP does not release
// the groups claim; every admin action is attributable to the session user.
function isAdmin(user: OidcUser | undefined): boolean {
    if (!user) {
        return false;
    }
    if (config.adminGroups.length > 0) {
        const groups = user.groups ?? [];
        if (groups.some((g) => config.adminGroups.includes(g))) {
            return true;
        }
    }
    return adminList.isAdmin(user.username);
}

function requireAdmin(req: Request, res: Response, next: NextFunction): void {
    if (!req.session.user) {
        res.status(401).json({ error: "not signed in" });
        return;
    }
    if (!isAdmin(req.session.user)) {
        res.status(403).json({ error: "admin only" });
        return;
    }
    next();
}

// LDAP is only consulted when the configured service list actually contains
// a cluster-backed entry (Slurm or file-mcp).  A lookup failure hides those
// services rather than offering a choice that cannot be minted; the MCP
// server's own current-access check remains the authoritative gate for any
// token that does exist.
async function clusterAccessForUser(user: OidcUser | undefined): Promise<ClusterAccess> {
    if (!user || !config.services.some((s) => s.slurmCluster)) {
        return NO_CLUSTER_ACCESS;
    }
    try {
        return await clusterAccessFor(user.username);
    } catch (e) {
        log.warn("LDAP cluster-access lookup failed", {
            user: user.username,
            error: e instanceof Error ? e.message : String(e),
        });
        return NO_CLUSTER_ACCESS;
    }
}

async function visibleServices(user: OidcUser | undefined): Promise<Service[]> {
    const access = await clusterAccessForUser(user);
    return config.services.filter((s) => isClusterAllowed(s.slurmCluster, access));
}

async function canMintService(user: OidcUser, service: Service): Promise<boolean> {
    if (!service.slurmCluster) {
        return true;
    }
    const access = await clusterAccessForUser(user);
    return isClusterAllowed(service.slurmCluster, access);
}

export function registerRoutes(app: express.Express): void {
    app.get("/login", async (req: Request, res: Response) => {
        if (!config.oidc.enabled) {
            res.status(503).send("OIDC is not configured");
            return;
        }
        try {
            res.redirect(await buildAuthUrl({ silent: req.query.silent === "1" }));
        } catch (e) {
            log.error("Failed to build authorization URL:", e);
            res.status(500).send("could not start authorization");
        }
    });

    // config.oidc.redirectUri is a full URL (e.g. http://localhost:5000/auth/callback);
    // express routes on the path component only, so derive it here.
    const callbackPath = config.oidc.redirectUri
        ? new URL(config.oidc.redirectUri).pathname
        : "";
    app.get(callbackPath, async (req: Request, res: Response) => {
        const url = new URL(`${req.protocol}://${req.get("host")}${req.originalUrl}`);
        const state = url.searchParams.get("state") || "";
        const silent = isSilentAuthState(state);
        const oidcError = url.searchParams.get("error");

        if (oidcError) {
            discardAuthState(state);
            log.warn("OIDC authorization failed", {
                error: oidcError,
                description: url.searchParams.get("error_description") || undefined,
                silent,
            });
            if (silent) {
                // No usable IdP session (or consent): show the normal page
                // with its explicit sign-in button instead of an error.
                req.session.silentAttempted = true;
                res.redirect("/");
                return;
            }
            res.status(400).send("authorization failed");
            return;
        }

        try {
            const user = await handleCallback(url);
            req.session.user = user;
            req.session.silentAttempted = false;
            // Seed the UI language from the IdP's `locale` claim; without
            // one, prefer the browser's Accept-Language.  Mirrors the
            // chatbot's login seeding.
            req.session.language =
                mapLocaleToLanguage(user.locale) ?? languageFromRequest(req);
            // Best effort: do not hold up login on LDAP, and a disabled user
            // still reaches the mint endpoint where the same check runs.
            void syncAccountState(user.username);
            res.redirect("/");
        } catch (e) {
            log.error("OIDC callback failed:", e);
            if (silent) {
                req.session.silentAttempted = true;
                res.redirect("/");
                return;
            }
            res.status(400).send("authorization failed");
        }
    });

    app.get("/logout", (req: Request, res: Response) => {
        // Sign out of this app only.  Keep the (now anonymous) session so
        // the next request does not immediately re-enter silent SSO against
        // the still-valid IdP session.
        req.session.user = undefined;
        req.session.silentAttempted = true;
        req.session.save(() => res.redirect("/"));
    });

    app.get("/api/session", (req: Request, res: Response) => {
        if (!req.session.user) {
            res.status(401).json({ error: "not signed in" });
            return;
        }
        res.json({
            user: req.session.user,
            language: req.session.language ?? "en",
            isAdmin: isAdmin(req.session.user),
        });
    });

    app.post("/api/language", requireUser, (req: Request, res: Response) => {
        const lang = (req.body ?? {}).language;
        if (lang !== "en" && lang !== "fr") {
            res.status(400).json({ error: 'language must be "en" or "fr"' });
            return;
        }
        req.session.language = lang;
        res.json({ ok: true, language: lang });
    });

    app.get("/api/services", async (req: Request, res: Response) => {
        // Another login/visit trigger for the LDAP disable check.  The sweep
        // covers users who never come back; this catches an active session.
        if (req.session.user) void syncAccountState(req.session.user.username);
        res.json({ services: await visibleServices(req.session.user) });
    });

    app.post("/api/tokens", requireUser, async (req: Request, res: Response) => {
        const user = req.session.user!;
        if (isManualBlacklisted(user.username)) {
            res.status(403).json({ error: "your account is blacklisted" });
            return;
        }
        // Check the directory before minting any service, including the
        // non-cluster ones.  A successful lookup also clears a stale
        // automatic block if access has been restored.
        const accountState = await syncAccountState(user.username);
        if (accountState === "disabled" || isAutoBlacklisted(user.username)) {
            res.status(403).json({ error: "your account is disabled" });
            return;
        }
        if (isBlacklisted(user.username)) {
            // Defensive: only a manual entry can remain at this point.
            res.status(403).json({ error: "your account is blacklisted" });
            return;
        }
        const body = (req.body ?? {}) as { service?: string; ttl_days?: number; name?: string };
        const services = config.services;
        const svc = services.find((s: Service) => s.id === body.service);
        if (!svc) {
            res.status(400).json({ error: `unknown service; expected one of ${services.map((s) => s.id).join(", ")}` });
            return;
        }
        if (!(await canMintService(user, svc))) {
            res.status(403).json({ error: "no access to this service" });
            return;
        }
        const ttlDays = Number.isFinite(body.ttl_days as number) && (body.ttl_days as number) > 0
            ? Math.round(body.ttl_days as number)
            : config.token.ttlDays;
        // Optional display name: trimmed, capped so the payload stays small.
        const name = typeof body.name === "string"
            ? body.name.trim().slice(0, 64) || undefined
            : undefined;
        let issued;
        try {
            issued = issueToken(user.username, svc.id, ttlDays, {
                groups: user.groups,
                name,
            });
        } catch {
            // issueToken refuses blocked users (defence in depth).
            res.status(403).json({
                error: isAutoBlacklisted(user.username)
                    ? "your account is disabled"
                    : "your account is blacklisted",
            });
            return;
        }
        res.json({ token: issued.token, claims: { sub: issued.sub, svc: issued.svc, iat: issued.iat, exp: issued.exp, jti: issued.jti, name: issued.name } });
    });

    app.get("/api/tokens", requireUser, (req: Request, res: Response) => {
        const user = req.session.user!;
        res.json({ tokens: listIssued(user.username) });
    });

    app.post("/api/tokens/:jti/revoke", requireUser, (req: Request, res: Response) => {
        const user = req.session.user!;
        if (!revoke(req.params.jti, user.username)) {
            res.status(404).json({ error: "no such token" });
            return;
        }
        res.json({ ok: true });
    });

    // ------------------------------------------------------------ admin --

    const admin = (req: Request): string => req.session.user!.username;
    const target = (value: unknown): string =>
        (Array.isArray(value) ? value[0] : value)?.toString().trim() ?? "";

    app.get("/api/admin/users", requireAdmin, (_req: Request, res: Response) => {
        res.json({ users: listUsers() });
    });

    app.get("/api/admin/tokens", requireAdmin, (req: Request, res: Response) => {
        const sub = target(req.query.sub);
        if (!sub) {
            res.status(400).json({ error: "missing ?sub=<username>" });
            return;
        }
        res.json({
            sub,
            tokens: listIssued(sub),
            blacklisted: isBlacklisted(sub),
            disabled: isAutoBlacklisted(sub),
        });
    });

    app.post("/api/admin/tokens/:jti/revoke", requireAdmin, (req: Request, res: Response) => {
        const jti = req.params.jti;
        if (!adminRevoke(jti)) {
            res.status(404).json({ error: "no such token" });
            return;
        }
        log.log("admin action", { action: "revoke token", admin: admin(req), jti });
        res.json({ ok: true });
    });

    app.post("/api/admin/users/:sub/revoke-all", requireAdmin, (req: Request, res: Response) => {
        const sub = target(req.params.sub);
        const revoked = revokeAllFor(sub);
        log.log("admin action", {
            action: "revoke all", admin: admin(req), target: sub,
            count: revoked.length,
        });
        res.json({ ok: true, revoked });
    });

    app.get("/api/admin/blacklist", requireAdmin, (_req: Request, res: Response) => {
        // Keep `users` as the manual abuse blacklist (the only list an admin
        // can clear) and expose automatic account-disable blocks separately.
        res.json({
            users: listManualBlacklisted(),
            disabled: listAutoBlacklisted(),
        });
    });

    // Blacklist a user: blocks new issuance, revokes all current tokens,
    // and the MCP servers reject their tokens at verify time within ~15s.
    app.post("/api/admin/blacklist", requireAdmin, (req: Request, res: Response) => {
        const sub = target((req.body ?? {}).sub);
        if (!sub) {
            res.status(400).json({ error: "missing sub" });
            return;
        }
        const { added, revoked } = blacklistUser(sub);
        log.log("admin action", {
            action: "blacklist", admin: admin(req), target: sub,
            added, revoked: revoked.length,
        });
        res.json({ ok: true, added, revoked });
    });

    app.delete("/api/admin/blacklist", requireAdmin, (req: Request, res: Response) => {
        const sub = target(req.query.sub) || target((req.body ?? {}).sub);
        if (!sub) {
            res.status(400).json({ error: "missing sub" });
            return;
        }
        if (!unblacklistUser(sub)) {
            if (isAutoBlacklisted(sub)) {
                res.status(409).json({
                    error: "account is disabled; the automatic block clears when access is restored",
                });
                return;
            }
            res.status(404).json({ error: "not blacklisted" });
            return;
        }
        log.log("admin action", { action: "unblacklist", admin: admin(req), target: sub });
        res.json({ ok: true, stillDisabled: isAutoBlacklisted(sub) });
    });
}
