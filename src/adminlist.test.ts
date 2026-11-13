import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

// Keep this test offline: config reads env at import time, so set the required
// secrets before importing the module under test.
process.env.TOKEN_HMAC_SECRET = "test-hmac-secret";
process.env.SESSION_SECRET = "test-session-secret";

const { AdminList } = await import("./adminlist");

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("missing file is empty", () => {
    const list = new AdminList("/nonexistent/admin-users.json", 0.5);
    assert.equal(list.isAdmin("alice"), false);
    assert.equal(list.isAdmin(""), false);
});

test("parses dict and array forms, case-insensitive", async (t) => {
    const dir = await mkdtemp(path.join(tmpdir(), "adminlist-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const p = path.join(dir, "admin-users.json");
    await writeFile(p, JSON.stringify({ adminUsernames: ["Alice", "bob"] }));
    const list = new AdminList(p, 0.5);
    assert.equal(list.isAdmin("alice"), true);
    assert.equal(list.isAdmin("BOB"), true);
    assert.equal(list.isAdmin("mallory"), false);

    // mtime+resize normally differ; wait past reload_seconds to be safe.
    await sleep(600);
    await writeFile(p, JSON.stringify(["carol"]));
    await sleep(600);
    assert.equal(list.isAdmin("carol"), true);
    assert.equal(list.isAdmin("alice"), false);
});

test("accepts the 'admin' alias key", async (t) => {
    const dir = await mkdtemp(path.join(tmpdir(), "adminlist-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const p = path.join(dir, "admin-users.json");
    await writeFile(p, JSON.stringify({ admin: ["zoe"] }));
    const list = new AdminList(p, 0.5);
    assert.equal(list.isAdmin("zoe"), true);
});

test("invalid json keeps the last good state", async (t) => {
    const dir = await mkdtemp(path.join(tmpdir(), "adminlist-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const p = path.join(dir, "admin-users.json");
    await writeFile(p, JSON.stringify(["alice"]));
    const list = new AdminList(p, 0.5);
    assert.equal(list.isAdmin("alice"), true);

    await sleep(600);
    await writeFile(p, "{ not json");
    await sleep(600);
    // Not dropped wholesale on a transiently-invalid file.
    assert.equal(list.isAdmin("alice"), true);
});
