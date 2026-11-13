// Cluster-access rules derived from the data-centre LDAP directory.
//
// Trillium and Trillium-GPU are Alliance-managed: `ccServiceAccess` carries
// `trillium-access`, and the GPU subcluster inherits it.  Legacy SciNet local
// accounts use `x-access=trillium` instead, but only while the account is
// enabled.
//
// Balam is a UofT-managed cluster.  Its entitlement is membership in the
// `lcl_balam` POSIX group, but the sysadmins require every Balam user to hold
// current Trillium access as well.  When an account is disabled or expires it
// loses Trillium access but remains in `lcl_balam` until the Accelerator Group
// asks for removal.  Balam access is therefore the intersection:
// `lcl_balam` membership AND Trillium access.
//
// An explicit `x-scinet-account-enabled=FALSE` is a person-level disable: it
// denies all cluster access, including an entitlement on another directory
// entry.  Alliance entries do not normally carry the local-account flag, so
// an absent flag does not block the Alliance path; it does block the local
// `x-access` paths, which require a positive TRUE.

export type SlurmCluster = "trillium" | "trillium-gpu" | "balam";

export type ClusterAccess = Readonly<Record<SlurmCluster, boolean>>;

export const NO_CLUSTER_ACCESS: ClusterAccess = {
    trillium: false,
    "trillium-gpu": false,
    balam: false,
};

// The subset of a user's LDAP entry that matters for cluster access.
export type DirectoryAccess = {
    ccServiceAccess: string[];
    xAccess: string[];
    enabled?: boolean;
};

function normalise(value: string): string {
    return value.trim().toLowerCase();
}

export function evaluateClusterAccess(entry: DirectoryAccess | undefined): ClusterAccess {
    if (!entry || entry.enabled === false) {
        return NO_CLUSTER_ACCESS;
    }

    const services = new Set(entry.ccServiceAccess.map(normalise));
    const systems = new Set(entry.xAccess.map(normalise));

    // Alliance-managed Trillium access.  The GPU subcluster is part of the
    // same entitlement; there is no separate trillium-gpu-access value.
    const allianceTrillium = services.has("trillium-access");
    // Legacy local-account access requires the account to be enabled.  A
    // missing flag is not positive evidence, so it does not grant access.
    const localTrillium = entry.enabled === true && systems.has("trillium");
    const trillium = allianceTrillium || localTrillium;

    // Balam is gated on lcl_balam group membership AND Trillium access; the
    // group check is person-level and therefore applied in
    // evaluateClusterAccesses, not from a single entry.
    return {
        trillium,
        "trillium-gpu": trillium,
        balam: false,
    };
}

// A person can have two directory entries: an Alliance `uid` entry and a
// separate SciNet-local `cn` entry.  A person-level disable is authoritative:
// an explicit `x-scinet-account-enabled=FALSE` on any entry vetoes all cluster
// access, including an Alliance `ccServiceAccess` entitlement.  Otherwise,
// evaluate each entry independently and union the results.
//
// `balamMember` comes from a separate `lcl_balam` group lookup.  Balam also
// requires Trillium access, so a group member who has lost Trillium access
// (disabled/expired) is denied without needing removal from the group.
export function evaluateClusterAccesses(
    entries: DirectoryAccess[],
    balamMember = false,
): ClusterAccess {
    if (entries.some((entry) => entry.enabled === false)) {
        return NO_CLUSTER_ACCESS;
    }

    let trillium = false;
    for (const entry of entries) {
        trillium = trillium || evaluateClusterAccess(entry).trillium;
    }
    return {
        trillium,
        "trillium-gpu": trillium,
        balam: balamMember && trillium,
    };
}

export function isClusterAllowed(
    cluster: SlurmCluster | undefined,
    access: ClusterAccess,
): boolean {
    return cluster === undefined || access[cluster];
}
