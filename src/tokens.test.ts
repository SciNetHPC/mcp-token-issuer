import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

// Set env before the modules are (dynamically) imported, since config
// reads these at import time.
process.env.TOKEN_HMAC_SECRET = "test-hmac-secret";
process.env.SESSION_SECRET = "test-session-secret";

const {
    signToken,
    verifyToken,
    TOKEN_VERSION,
    isRevoked,
    issueToken,
    listIssued,
    revoke,
    initStore,
    flushStore,
    adminRevoke,
    revokeAllFor,
    isBlacklisted,
    isAutoBlacklisted,
    isManualBlacklisted,
    listBlacklisted,
    listAutoBlacklisted,
    listManualBlacklisted,
    blacklistUser,
    unblacklistUser,
    autoBlacklistUser,
    autoUnblacklistUser,
    listUsers,
} = await import("./tokens");

test("sign/verify round trip", () => {
    const { token, jti } = signToken({ sub: "alice", svc: "filemcp" });
    assert.ok(token.startsWith(TOKEN_VERSION + "."));
    const claims = verifyToken(token, "filemcp");
    assert.equal(claims?.sub, "alice");
    assert.equal(claims?.svc, "filemcp");
    assert.ok(claims!.exp > claims!.iat);
    assert.equal(claims!.jti, jti);
});

test("token is bound to its service", () => {
    const { token } = signToken({ sub: "alice", svc: "filemcp" });
    assert.equal(verifyToken(token, "filemcp")?.sub, "alice");
    assert.equal(verifyToken(token, "neo4j"), null);
});

test("groups claim is stamped and covered by the signature", () => {
    const { token, groups } = signToken({ sub: "alice", svc: "filemcp", groups: ["cc-staff"] });
    assert.deepEqual(groups, ["cc-staff"]);
    const claims = verifyToken(token, "filemcp");
    assert.deepEqual(claims?.groups, ["cc-staff"]);
    // No groups when none were provided.
    const bare = signToken({ sub: "alice", svc: "filemcp" });
    assert.equal(bare.groups, undefined);
    assert.equal(verifyToken(bare.token, "filemcp")?.groups, undefined);
});

test("name claim is stamped and covered by the signature", () => {
    const { token, name } = signToken({ sub: "alice", svc: "filemcp", name: "prod ccdb" });
    assert.equal(name, "prod ccdb");
    const claims = verifyToken(token, "filemcp");
    assert.equal(claims?.name, "prod ccdb");
    // Absent / not tamperable when omitted.
    const bare = signToken({ sub: "alice", svc: "filemcp" });
    assert.equal(bare.name, undefined);
    assert.equal(verifyToken(bare.token, "filemcp")?.name, undefined);
});

test("tampered token is rejected", () => {
    const { token } = signToken({ sub: "alice", svc: "filemcp" });
    const parts = token.split(".");
    const forged = Buffer.from(
        JSON.stringify({ sub: "mallory", svc: "filemcp", iat: 1, exp: 1e10, jti: "x" }),
    ).toString("base64url");
    assert.equal(verifyToken(`${parts[0]}.${forged}.${parts[2]}`, "filemcp"), null);
    assert.equal(
        verifyToken(`${parts[0]}.${parts[1]}.${"A".repeat(parts[2].length)}`, "filemcp"),
        null,
    );
});

test("expired token is rejected", () => {
    const { token } = signToken({ sub: "alice", svc: "filemcp", iat: 1000, exp: 1001 });
    assert.equal(verifyToken(token, "filemcp"), null);
});

test("wrong version is rejected", () => {
    const { token } = signToken({ sub: "alice", svc: "filemcp" });
    const scaled = "fmcpv9" + token.slice(TOKEN_VERSION.length);
    assert.equal(verifyToken(scaled, "filemcp"), null);
});

test("issue, list and revoke via the store", async (t) => {
    const dir = await mkdtemp(path.join(tmpdir(), "token-issuer-"));
    t.after(async () => {
        await flushStore();
        await rm(dir, { recursive: true, force: true });
    });
    process.env.TOKEN_STORE_PATH = path.join(dir, "store.json");
    await initStore();

    const { token, jti } = issueToken("bob", "filemcp", 30);
    const claims = verifyToken(token, "filemcp");
    assert.equal(claims?.sub, "bob");
    assert.deepEqual(listIssued("bob").map((c) => c.jti), [jti]);
    assert.equal(listIssued("alice").length, 0);
    assert.ok(!isRevoked(jti));
    assert.equal(revoke(jti, "alice"), false); // not bob's token as alice
    assert.equal(revoke(jti, "bob"), true);
    assert.ok(isRevoked(jti));
    assert.equal(listIssued("bob").length, 0);
});

test("admin revocation and blacklist via the store", async (t) => {
    const dir = await mkdtemp(path.join(tmpdir(), "token-issuer-admin-"));
    t.after(async () => {
        await flushStore();
        await rm(dir, { recursive: true, force: true });
    });
    process.env.TOKEN_STORE_PATH = path.join(dir, "store2.json");
    await initStore();

    // Seed two users with a couple of tokens each.
    const a1 = issueToken("alice", "filemcp", 30);
    const a2 = issueToken("alice", "ccdb", 30);
    const b1 = issueToken("bob", "filemcp", 30);
    assert.deepEqual(listIssued("alice").map((c) => c.jti), [a1.jti, a2.jti]);
    assert.ok(listUsers().includes("alice"));
    assert.ok(listUsers().includes("bob"));

    // Admin can revoke a token that isn't theirs.
    assert.equal(adminRevoke(b1.jti), true);
    assert.ok(isRevoked(b1.jti));
    assert.equal(adminRevoke(b1.jti), false); // already gone

    // revokeAllFor kills every token a user currently has.
    assert.deepEqual(revokeAllFor("alice"), [a1.jti, a2.jti]);
    assert.equal(listIssued("alice").length, 0);
    assert.ok(isRevoked(a1.jti) && isRevoked(a2.jti));

    // Issue a fresh one, then blacklist: adds the user and revokes afresh.
    const a3 = issueToken("alice", "filemcp", 30);
    const { added, revoked } = blacklistUser("alice");
    assert.equal(added, true);
    assert.deepEqual(revoked, [a3.jti]);
    assert.ok(isBlacklisted("alice"));
    assert.ok(isBlacklisted("ALICE")); // case-insensitive
    assert.deepEqual(listBlacklisted(), ["alice"]);
    assert.equal(listIssued("alice").length, 0);
    assert.throws(() => issueToken("alice", "filemcp", 30), /blacklisted/);
    // Blacklisting twice doesn't duplicate the entry.
    blacklistUser("alice");
    assert.deepEqual(listBlacklisted(), ["alice"]);

    // Unblacklist lets the user issue again.
    assert.equal(unblacklistUser("alice"), true);
    assert.ok(!isBlacklisted("alice"));
    assert.equal(unblacklistUser("alice"), false); // not present anymore
    assert.ok(issueToken("alice", "filemcp", 30));
});

test("automatic disable block revokes, blocks, and clears on restore", async (t) => {
    const dir = await mkdtemp(path.join(tmpdir(), "token-issuer-auto-"));
    t.after(async () => {
        await flushStore();
        await rm(dir, { recursive: true, force: true });
    });
    process.env.TOKEN_STORE_PATH = path.join(dir, "store.json");
    await initStore();

    const { jti } = issueToken("carol", "docs", 30);
    const { added, revoked } = autoBlacklistUser("carol");
    assert.equal(added, true);
    assert.deepEqual(revoked, [jti]);
    assert.ok(isRevoked(jti));
    assert.ok(isAutoBlacklisted("carol"));
    assert.ok(isBlacklisted("carol")); // effective block
    assert.ok(!isManualBlacklisted("carol"));
    assert.deepEqual(listAutoBlacklisted(), ["carol"]);
    assert.deepEqual(listManualBlacklisted(), []);
    assert.throws(() => issueToken("carol", "docs", 30), /blacklisted/);

    // Idempotent: a second sweep still catches any newly minted token.
    const again = autoBlacklistUser("carol");
    assert.equal(again.added, false);
    assert.deepEqual(again.revoked, []);

    // No manual blacklist: restore clears the effective block.
    assert.equal(autoUnblacklistUser("carol"), true);
    assert.ok(!isAutoBlacklisted("carol"));
    assert.ok(!isBlacklisted("carol"));
    assert.ok(issueToken("carol", "docs", 30));
    assert.equal(autoUnblacklistUser("carol"), false);
});

test("manual blacklist survives automatic restore", async (t) => {
    const dir = await mkdtemp(path.join(tmpdir(), "token-issuer-manual-auto-"));
    t.after(async () => {
        await flushStore();
        await rm(dir, { recursive: true, force: true });
    });
    process.env.TOKEN_STORE_PATH = path.join(dir, "store.json");
    await initStore();

    const { jti } = issueToken("dave", "filemcp", 30);
    blacklistUser("dave");
    autoBlacklistUser("dave");
    assert.ok(isManualBlacklisted("dave"));
    assert.ok(isAutoBlacklisted("dave"));
    assert.ok(isBlacklisted("dave"));

    assert.equal(autoUnblacklistUser("dave"), true);
    assert.ok(isManualBlacklisted("dave"));
    assert.ok(!isAutoBlacklisted("dave"));
    assert.ok(isBlacklisted("dave")); // manual remains
    assert.ok(isRevoked(jti));
    assert.throws(() => issueToken("dave", "filemcp", 30), /blacklisted/);

    assert.equal(unblacklistUser("dave"), true);
    assert.ok(!isBlacklisted("dave"));
    assert.ok(issueToken("dave", "filemcp", 30));
});

test("an old ordinary blacklist is migrated as manual", async (t) => {
    const dir = await mkdtemp(path.join(tmpdir(), "token-issuer-migrate-"));
    t.after(async () => {
        await flushStore();
        await rm(dir, { recursive: true, force: true });
    });
    const storePath = path.join(dir, "store.json");
    process.env.TOKEN_STORE_PATH = storePath;
    await writeFile(storePath, JSON.stringify({
        issued: {},
        revokedJtis: [],
        blacklisted: ["legacy"],
    }));
    await initStore();

    assert.ok(isManualBlacklisted("legacy"));
    assert.ok(!isAutoBlacklisted("legacy"));
    assert.ok(isBlacklisted("legacy"));
    assert.equal(unblacklistUser("legacy"), true);
    assert.ok(!isBlacklisted("legacy"));
});
