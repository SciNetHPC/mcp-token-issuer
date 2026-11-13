import test from "node:test";
import assert from "node:assert/strict";
import {
    evaluateClusterAccess,
    evaluateClusterAccesses,
    isClusterAllowed,
    NO_CLUSTER_ACCESS,
} from "./accessrules";

const ALLIANCE_TRILLIUM = {
    ccServiceAccess: ["trillium-access"],
    xAccess: [],
};

test("no LDAP entry means no cluster access", () => {
    assert.deepEqual(evaluateClusterAccess(undefined), NO_CLUSTER_ACCESS);
});

test("trillium-access grants Trillium and Trillium-GPU, not Balam", () => {
    assert.deepEqual(evaluateClusterAccess(ALLIANCE_TRILLIUM), {
        trillium: true,
        "trillium-gpu": true,
        balam: false,
    });
});

test("Alliance access does not require the local-account flag", () => {
    assert.deepEqual(evaluateClusterAccess({ ...ALLIANCE_TRILLIUM, enabled: undefined }), {
        trillium: true,
        "trillium-gpu": true,
        balam: false,
    });
});

test("an explicitly disabled account loses all access", () => {
    assert.deepEqual(evaluateClusterAccess({ ...ALLIANCE_TRILLIUM, enabled: false }), NO_CLUSTER_ACCESS);
});

test("legacy x-access=trillium requires an enabled account", () => {
    assert.deepEqual(
        evaluateClusterAccess({ ccServiceAccess: [], xAccess: ["trillium"], enabled: true }),
        { trillium: true, "trillium-gpu": true, balam: false },
    );
    assert.deepEqual(
        evaluateClusterAccess({ ccServiceAccess: [], xAccess: ["trillium"], enabled: undefined }),
        NO_CLUSTER_ACCESS,
    );
});

test("Balam requires both lcl_balam membership and Trillium access", () => {
    // Group membership without current Trillium access (a disabled or expired
    // account that remains in lcl_balam) does not grant Balam.
    assert.deepEqual(evaluateClusterAccesses([], true), NO_CLUSTER_ACCESS);
    assert.deepEqual(
        evaluateClusterAccesses([{ ccServiceAccess: ["nibi-access"], xAccess: [] }], true),
        NO_CLUSTER_ACCESS,
    );
    // Trillium access without group membership does not grant Balam either.
    assert.deepEqual(evaluateClusterAccesses([ALLIANCE_TRILLIUM], false), {
        trillium: true,
        "trillium-gpu": true,
        balam: false,
    });
    // The intersection grants Balam.
    assert.deepEqual(evaluateClusterAccesses([ALLIANCE_TRILLIUM], true), {
        trillium: true,
        "trillium-gpu": true,
        balam: true,
    });
});

test("access values are case-insensitive", () => {
    assert.deepEqual(
        evaluateClusterAccess({
            ccServiceAccess: ["TRILLIUM-ACCESS"],
            xAccess: [],
            enabled: undefined,
        }),
        { trillium: true, "trillium-gpu": true, balam: false },
    );
});

test("Alliance and local entries are combined with Balam membership", () => {
    assert.deepEqual(
        evaluateClusterAccesses([
            ALLIANCE_TRILLIUM,
            { ccServiceAccess: [], xAccess: ["trillium"], enabled: true },
        ], true),
        { trillium: true, "trillium-gpu": true, balam: true },
    );
});

test("an explicitly disabled entry vetoes every other entitlement", () => {
    assert.deepEqual(
        evaluateClusterAccesses([
            ALLIANCE_TRILLIUM,
            { ccServiceAccess: [], xAccess: [], enabled: false },
        ], true),
        NO_CLUSTER_ACCESS,
    );
});

test("a disabled Alliance entry also vetoes Balam membership", () => {
    assert.deepEqual(
        evaluateClusterAccesses([
            { ...ALLIANCE_TRILLIUM, enabled: false },
            { ccServiceAccess: [], xAccess: [] },
        ], true),
        NO_CLUSTER_ACCESS,
    );
});

test("no entries means no access, even with Balam membership", () => {
    assert.deepEqual(evaluateClusterAccesses([]), NO_CLUSTER_ACCESS);
    assert.deepEqual(evaluateClusterAccesses([], true), NO_CLUSTER_ACCESS);
});

test("isClusterAllowed only restricts cluster-backed services", () => {
    const access = { trillium: true, "trillium-gpu": true, balam: false };
    assert.equal(isClusterAllowed(undefined, access), true);
    assert.equal(isClusterAllowed("trillium", access), true);
    assert.equal(isClusterAllowed("trillium-gpu", access), true);
    assert.equal(isClusterAllowed("balam", access), false);
});
