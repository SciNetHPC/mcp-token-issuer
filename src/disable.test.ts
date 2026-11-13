import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

process.env.TOKEN_HMAC_SECRET = "test-hmac-secret";
process.env.SESSION_SECRET = "test-session-secret";

const {
    initStore,
    issueToken,
    isAutoBlacklisted,
    isRevoked,
    flushStore,
} = await import("./tokens");
const { syncAccountState, sweepOnce } = await import("./disable");

test("disable check blocks, revokes, and clears on restore", async (t) => {
    const dir = await mkdtemp(path.join(tmpdir(), "token-issuer-disable-"));
    t.after(async () => {
        await flushStore();
        await rm(dir, { recursive: true, force: true });
    });
    process.env.TOKEN_STORE_PATH = path.join(dir, "store.json");
    await initStore();

    const { jti } = issueToken("erin", "docs", 30);
    assert.equal(await syncAccountState("erin", async () => "disabled"), "disabled");
    assert.ok(isAutoBlacklisted("erin"));
    assert.ok(isRevoked(jti));
    assert.throws(() => issueToken("erin", "docs", 30), /blacklisted/);

    assert.equal(await syncAccountState("erin", async () => "active"), "restored");
    assert.ok(!isAutoBlacklisted("erin"));
    assert.ok(issueToken("erin", "docs", 30));
    assert.equal(await syncAccountState("erin", async () => "active"), "active");
});

test("an unknown directory state does not clear or apply a block", async (t) => {
    const dir = await mkdtemp(path.join(tmpdir(), "token-issuer-unknown-"));
    t.after(async () => {
        await flushStore();
        await rm(dir, { recursive: true, force: true });
    });
    process.env.TOKEN_STORE_PATH = path.join(dir, "store.json");
    await initStore();

    assert.equal(await syncAccountState("frank", async () => "disabled"), "disabled");
    assert.ok(isAutoBlacklisted("frank"));
    assert.equal(await syncAccountState("frank", async () => "unknown"), "unknown");
    assert.ok(isAutoBlacklisted("frank"));

    assert.equal(await syncAccountState("frank", async () => "active"), "restored");
    assert.ok(!isAutoBlacklisted("frank"));
});

test("the sweep includes disabled users after their tokens are gone", async (t) => {
    const dir = await mkdtemp(path.join(tmpdir(), "token-issuer-sweep-"));
    t.after(async () => {
        await flushStore();
        await rm(dir, { recursive: true, force: true });
    });
    process.env.TOKEN_STORE_PATH = path.join(dir, "store.json");
    await initStore();

    const ivan = issueToken("ivan", "docs", 30);
    issueToken("judy", "docs", 30);

    const seen = new Set<string>();
    await sweepOnce(async (user) => {
        seen.add(user);
        return user === "ivan" ? "disabled" : "active";
    });
    assert.ok(seen.has("ivan"));
    assert.ok(seen.has("judy"));
    assert.ok(isAutoBlacklisted("ivan"));
    assert.ok(isRevoked(ivan.jti));
    assert.ok(!isAutoBlacklisted("judy"));

    // Ivan has no live tokens now, but must still be rechecked so the block
    // can clear when access is restored.
    await sweepOnce(async () => "active");
    assert.ok(!isAutoBlacklisted("ivan"));
});
