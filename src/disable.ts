import { config } from "./config";
import { accountStateFor, type AccountState } from "./ldapaccess";
import { log } from "./log";
import {
    autoBlacklistUser,
    autoUnblacklistUser,
    listAutoBlacklisted,
    listUsers,
} from "./tokens";

export type SyncResult = "disabled" | "restored" | "active" | "unknown";

type Lookup = (username: string) => Promise<AccountState>;

// Share one LDAP lookup per user when the sweep, a login, and a mint request
// arrive together.  A shared promise also prevents a mint from slipping
// through while the sweep is in the middle of applying a block.
const syncing = new Map<string, Promise<SyncResult>>();

export function syncAccountState(username: string, lookup: Lookup = accountStateFor): Promise<SyncResult> {
    const trimmed = username.trim();
    const key = trimmed.toLowerCase();
    if (!key) return Promise.resolve("unknown");

    const existing = syncing.get(key);
    if (existing) return existing;

    const task = (async (): Promise<SyncResult> => {
        try {
            const state = await lookup(trimmed);
            if (state === "disabled") {
                const { added, revoked } = autoBlacklistUser(trimmed);
                if (added || revoked.length > 0) {
                    log.log("account disabled: revoked tokens and blocked new issuance", {
                        user: trimmed,
                        added,
                        revoked: revoked.length,
                    });
                }
                return "disabled";
            }
            if (state === "active") {
                const removed = autoUnblacklistUser(trimmed);
                if (removed) {
                    log.log("account access restored: automatic block removed", {
                        user: trimmed,
                    });
                }
                return removed ? "restored" : "active";
            }
            return "unknown";
        } catch (e) {
            log.warn("account state lookup failed", {
                user: trimmed,
                error: e instanceof Error ? e.message : String(e),
            });
            return "unknown";
        }
    })().finally(() => {
        syncing.delete(key);
    });

    syncing.set(key, task);
    return task;
}

/**
 * Recheck every user who either has a live token or is under the automatic
 * disable block.  The latter is important: after the initial revoke they may
 * have no tokens left, so they would otherwise never be seen again and the
 * block would not clear when access is restored.
 */
export async function sweepOnce(lookup: Lookup = accountStateFor): Promise<void> {
    const users = new Set([...listUsers(), ...listAutoBlacklisted()]);
    if (users.size === 0) return;

    const list = [...users].sort((a, b) => a.localeCompare(b));
    const concurrency = Math.max(1, config.accountDisable.sweepConcurrency);
    for (let i = 0; i < list.length; i += concurrency) {
        await Promise.all(
            list.slice(i, i + concurrency).map((user) => syncAccountState(user, lookup)),
        );
    }
}

let timer: NodeJS.Timeout | null = null;
let running = false;

export function startDisableSweep(): void {
    const seconds = config.accountDisable.sweepSeconds;
    if (!config.ldap.enabled) {
        log.warn("LDAP is not configured; automatic account-disable checks are off");
        return;
    }
    if (seconds <= 0) {
        log.warn("ACCOUNT_DISABLE_SWEEP_SECONDS <= 0; automatic account-disable checks are off");
        return;
    }

    const run = (): void => {
        if (running) return;
        running = true;
        void sweepOnce()
            .catch((e) => {
                log.warn("account-disable sweep failed", {
                    error: e instanceof Error ? e.message : String(e),
                });
            })
            .finally(() => {
                running = false;
            });
    };

    // Run once at startup so a disable that happened while the issuer was
    // down is applied without waiting for the first interval.
    run();
    timer = setInterval(run, seconds * 1000);
    timer.unref();
    log.log(`automatic account-disable check every ${seconds}s`);
}

export function stopDisableSweep(): void {
    if (timer) clearInterval(timer);
    timer = null;
}
