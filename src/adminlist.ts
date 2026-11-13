import { readFileSync, statSync } from "node:fs";
import { config } from "./config";

// Ops-maintained admin list on the shared token-issuer volume, mirroring
// file-mcp's StaffList: re-read on mtime (up to reloadSeconds), tolerates a
// missing or invalid file (keeps / empties the set), and normalises usernames
// to lowercase for case-insensitive matching.  Usernames are compared with
// `.toLowerCase()` (not casefold, which is unavailable without a dep).
//
// This is the fallback admin path for when the IdP does not release the
// ADMIN_GROUPS claim for every operator who needs it; group membership and
// this list are OR-ed together in routes.ts.
//
// File format (matching the staff-usernames.json convention on the volume):
//
//   {"adminUsernames": ["alice", "bob"]}      (also accepts "admin" as the key)
//   ["alice", "bob"]                          (bare array)
//
// Reads happen synchronously.  The file is tiny and re-statted at most every
// reloadSeconds, and it lives on the same small local bind mount as
// token-store.json, so this keeps the decision out of the async request path
// (exactly like file-mcp's StaffList).
export class AdminList {
    private readonly path_: string;
    private readonly reloadSeconds: number;
    private usernames_: Set<string> = new Set();
    private mtimeMs: number | null = null;
    private lastCheck = 0;
    private loadedOnce = false;

    constructor(listPath: string, reloadSeconds = 15) {
        this.path_ = listPath;
        this.reloadSeconds = Math.max(0.5, reloadSeconds);
    }

    isAdmin(username: string): boolean {
        this.maybeReload();
        const key = username.trim().toLowerCase();
        return key !== "" && this.usernames_.has(key);
    }

    private maybeReload(): void {
        const now = Date.now();
        if (this.loadedOnce && now - this.lastCheck < this.reloadSeconds * 1000) {
            return;
        }
        this.loadedOnce = true;
        this.lastCheck = now;
        let stat;
        try {
            stat = statSync(this.path_);
        } catch {
            // File not present (yet): no admins from this source.
            this.usernames_ = new Set();
            return;
        }
        if (stat.mtimeMs === this.mtimeMs) {
            return;
        }
        this.mtimeMs = stat.mtimeMs;
        let raw: string;
        try {
            raw = readFileSync(this.path_, "utf8");
        } catch {
            return;
        }
        let parsed: unknown;
        try {
            parsed = JSON.parse(raw);
        } catch {
            // Transiently invalid (e.g. mid-write by ops): keep the last good
            // state rather than dropping everyone.
            return;
        }
        let candidates: unknown = null;
        if (Array.isArray(parsed)) {
            candidates = parsed;
        } else if (parsed !== null && typeof parsed === "object") {
            const record = parsed as Record<string, unknown>;
            candidates = record.adminUsernames ?? record.admin;
        }
        if (Array.isArray(candidates)) {
            this.usernames_ = new Set(
                candidates
                    .filter((u): u is string => typeof u === "string")
                    .map((u) => u.trim().toLowerCase())
                    .filter((u) => u !== ""),
            );
        }
    }
}

// Single shared instance (the list is a cluster-wide property, not per-user).
export const adminList: AdminList = new AdminList(
    config.adminListPath,
    // Kept in sync with the token-store mtime reload so an admin change lands
    // as fast as a revocation change.
    15,
);
