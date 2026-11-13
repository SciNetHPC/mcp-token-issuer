import test from "node:test";
import assert from "node:assert/strict";

// Keep this test offline: config reads env at import time, and the empty
// LDAP_URL makes the lookup path return "no access" without opening a socket.
process.env.TOKEN_HMAC_SECRET = "test-hmac-secret";
process.env.SESSION_SECRET = "test-session-secret";
process.env.LDAP_URL = "";

const {
    accountStateFor,
    accountStateFromEntries,
    clusterAccessFor,
    escapeFilterValue,
    lookupDirectoryAccesses,
} = await import("./ldapaccess");
const { NO_CLUSTER_ACCESS } = await import("./accessrules");

test("LDAP filter values are escaped", () => {
    assert.equal(escapeFilterValue("alice"), "alice");
    assert.equal(escapeFilterValue("a*b(c)d\\e\0f"), "a\\2ab\\28c\\29d\\5ce\\00f");
});

test("no LDAP configuration means no cluster access", async () => {
    assert.deepEqual(await lookupDirectoryAccesses("alice"), []);
    assert.deepEqual(await clusterAccessFor("alice"), NO_CLUSTER_ACCESS);
    assert.equal(await accountStateFor("alice"), "unknown");
});

test("account state treats any explicit FALSE as disabled", () => {
    const base = { ccServiceAccess: [], xAccess: [] };
    assert.equal(accountStateFromEntries([]), "unknown");
    assert.equal(accountStateFromEntries([{ ...base, enabled: true }]), "active");
    assert.equal(accountStateFromEntries([{ ...base }]), "active");
    assert.equal(accountStateFromEntries([{ ...base, enabled: false }]), "disabled");
    assert.equal(
        accountStateFromEntries([
            { ...base, enabled: true },
            { ...base, enabled: false },
        ]),
        "disabled",
    );
});
