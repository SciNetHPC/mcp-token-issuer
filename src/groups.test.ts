import test from "node:test";
import assert from "node:assert/strict";

import { deriveGroups } from "./groups";

test("no groups and no ccServiceAccess -> undefined", () => {
    assert.equal(deriveGroups({}, {}), undefined);
});

test("cc_staff in ccServiceAccess -> ['cc-staff']", () => {
    assert.deepEqual(deriveGroups({ ccServiceAccess: ["cc_staff"] }, {}), ["cc-staff"]);
});

test("co_staff in ccServiceAccess -> ['cc-staff']", () => {
    assert.deepEqual(
        deriveGroups({ ccServiceAccess: ["co_staff", "trillium-access"] }, {}),
        ["cc-staff"],
    );
});

test("ccServiceAccess without staff values -> undefined", () => {
    assert.equal(
        deriveGroups({ ccServiceAccess: ["cc_active_users", "trillium-access"] }, {}),
        undefined,
    );
});

test("single-string ccServiceAccess (not array) handled", () => {
    assert.deepEqual(deriveGroups({ ccServiceAccess: "cc_staff" }, {}), ["cc-staff"]);
});

test("staff values are case-insensitive", () => {
    assert.deepEqual(deriveGroups({ ccServiceAccess: ["CC_STAFF"] }, {}), ["cc-staff"]);
});

test("genuine groups claim still passes through, merged with staff", () => {
    assert.deepEqual(
        deriveGroups({ groups: ["Engineering"], ccServiceAccess: ["cc_staff"] }, {}),
        ["engineering", "cc-staff"],
    );
});

test("ID-token roles claim still honoured", () => {
    assert.deepEqual(deriveGroups({}, { roles: "ScinetMember" }), ["scinetmember"]);
});

test("cc-staff not duplicated when both sources agree", () => {
    assert.deepEqual(
        deriveGroups({ groups: ["cc-staff"], ccServiceAccess: ["co_staff"] }, {}),
        ["cc-staff"],
    );
});
