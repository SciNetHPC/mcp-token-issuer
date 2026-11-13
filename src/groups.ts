// Staff-group derivation from the Alliance IdP's released claims.
//
// The IdP does not release a `groups` claim (confirmed in production:
// neither the ID token nor UserInfo carries one -- the chatbot logs
// `claim_keys` on every login).  Staff membership is instead released as
// the `ccServiceAccess` attribute, whose value list carries `cc_staff` /
// `co_staff` for staff (matched against the CCDB LDAP, where every human
// in the SciNet staff group is also in cc_staff or co_staff).
//
// `deriveGroups` folds those values into the single `cc-staff` group, so
// the MCP servers' STAFF_GROUPS default ("cc-staff", "scinet") keeps
// working without an IdP policy change.  A genuine `groups`/`roles` claim
// released later still passes through unchanged, and `cc-staff` is not
// duplicated when both sources agree.

const STAFF_ACCESS = new Set(["cc_staff", "co_staff"]);
const STAFF_GROUP = "cc-staff";

export function deriveGroups(
    userinfo: Record<string, unknown> | undefined,
    claims: Record<string, unknown> | undefined,
): string[] | undefined {
    const info = userinfo ?? {};
    const cl = claims ?? {};
    const rawGroups =
        (info as any).groups ?? (cl as any).groups ?? (cl as any).roles;
    let groups: string[] | undefined;
    if (Array.isArray(rawGroups)) {
        groups = rawGroups
            .filter((g): g is string => typeof g === "string")
            .map((g) => g.toLowerCase());
    } else if (typeof rawGroups === "string" && rawGroups) {
        groups = [rawGroups.toLowerCase()];
    }

    const service = (info as any).ccServiceAccess;
    const released = Array.isArray(service)
        ? service
        : typeof service === "string"
          ? [service]
          : [];
    const isStaff = released.some(
        (v: unknown) => typeof v === "string" && STAFF_ACCESS.has(v.toLowerCase()),
    );
    if (isStaff && !groups?.includes(STAFF_GROUP)) {
        groups = [...(groups ?? []), STAFF_GROUP];
    }

    return groups && groups.length > 0 ? groups : undefined;
}
