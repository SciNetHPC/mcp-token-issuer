import dotenv from "dotenv";
import type { SlurmCluster } from "./accessrules";
dotenv.config();

export type Service = {
    id: string;
    name: string;
    description?: string;
    // Optional French description rendered by the mint page when the session
    // language is French.  Falls back to `description` when absent.
    descriptionFr?: string;
    // Public MCP endpoint, e.g. "https://mcp.scinet.utoronto.ca/docs".
    // Shown on the mint page so users know what the token they mint unlocks.
    url?: string;
    // Set for services whose availability depends on current cluster access.
    // The issuer checks LDAP before listing or minting these.  The name is
    // historical: file-mcp uses it too because it serves Trillium files.
    slurmCluster?: SlurmCluster;
};

function env(name: string): string {
    const value = process.env[name];
    if (!value) {
        throw new Error(`Missing required environment variable ${name}`);
    }
    return value;
}

function envInt(name: string, fallback: number): number {
    const raw = process.env[name];
    if (!raw) return fallback;
    const n = Number.parseInt(raw, 10);
    if (Number.isNaN(n)) return fallback;
    return n;
}

// The cluster-backed service ids always carry their cluster marker, even if
// an operator-supplied SERVICES override forgets it.  This prevents an
// override from accidentally making a cluster service visible/mintable
// without LDAP.  file-mcp is included because it serves Trillium files.
const CLUSTER_BY_SERVICE: Record<string, SlurmCluster> = {
    "file-mcp": "trillium",
    "slurm-trillium": "trillium",
    "slurm-trillium-gpu": "trillium-gpu",
    "slurm-balam": "balam",
};

function withSlurmCluster(service: Service): Service {
    const cluster = CLUSTER_BY_SERVICE[service.id];
    return cluster ? { ...service, slurmCluster: cluster } : service;
}

function services(): Service[] {
    const raw = process.env.SERVICES;
    if (raw) {
        try {
            const parsed = JSON.parse(raw) as Service[];
            if (Array.isArray(parsed) && parsed.every((s) => s && s.id && s.name)) {
                return parsed.map(withSlurmCluster);
            }
        } catch {
            // fall through to the default below
        }
    }
    const defaults: Service[] = [
        {
            id: "file-mcp",
            name: "File MCP",
            description: "Read-only access to your cluster home, scratch, and project directories.",
            descriptionFr: "Accès en lecture seule à votre répertoire personnel, à votre espace scratch et à vos répertoires de projet sur la grappe.",
            url: "https://mcp.scinet.utoronto.ca/files",
        },
        {
            id: "ccdb",
            name: "CCDB MCP",
            description: "Read-only access to your own CCDB allocation and RAP records.",
            descriptionFr: "Accès en lecture seule à vos propres allocations CCDB et renseignements RAP.",
            url: "https://mcp.scinet.utoronto.ca/ccdb",
        },
        {
            id: "docs",
            name: "Docs MCP",
            description: "Search the Alliance and SciNet documentation (keyword and semantic search).",
            descriptionFr: "Recherchez dans la documentation d'Alliance et de SciNet (recherche par mots-clés et recherche sémantique).",
            url: "https://mcp.scinet.utoronto.ca/docs",
        },
        {
            id: "jobs",
            name: "Jobs MCP",
            description: "Read-only access to your own Slurm job history, queue position, and accounting records.",
            descriptionFr: "Accès en lecture seule à votre historique de tâches Slurm, à votre position dans la file d'attente et à vos données comptables.",
            url: "https://mcp.scinet.utoronto.ca/jobs",
        },
        {
            id: "status",
            name: "Status MCP",
            description: "Read-only snapshots of cluster status, node health, job co-tenancy, and home, scratch, and project storage usage and quotas.",
            descriptionFr: "Instantanés en lecture seule de l'état de la grappe, de l'état des nœuds, de la cohabitation des tâches et de l'utilisation et des quotas de stockage pour les répertoires home, scratch et project.",
            url: "https://mcp.scinet.utoronto.ca/status",
        },
        {
            id: "slurm-trillium",
            name: "Slurm MCP (Trillium)",
            description: "Read-only Slurm job, queue, and cluster information for Trillium.",
            descriptionFr: "Renseignements en lecture seule sur les tâches, la file d'attente et la grappe pour Trillium.",
            url: "https://mcp.scinet.utoronto.ca/slurm/trillium",
            slurmCluster: "trillium",
        },
        {
            id: "slurm-trillium-gpu",
            name: "Slurm MCP (Trillium-GPU)",
            description: "Read-only Slurm job, queue, and cluster information for Trillium-GPU.",
            descriptionFr: "Renseignements en lecture seule sur les tâches, la file d'attente et la grappe pour Trillium-GPU.",
            url: "https://mcp.scinet.utoronto.ca/slurm/trillium-gpu",
            slurmCluster: "trillium-gpu",
        },
        {
            id: "slurm-balam",
            name: "Slurm MCP (Balam)",
            description: "Read-only Slurm job, queue, and cluster information for Balam.",
            descriptionFr: "Renseignements en lecture seule sur les tâches, la file d'attente et la grappe pour Balam.",
            url: "https://mcp.scinet.utoronto.ca/slurm/balam",
            slurmCluster: "balam",
        },
    ];
    return defaults.map(withSlurmCluster);
}

export const config = {
    port: envInt("PORT", 5000),
    sessionSecret: env("SESSION_SECRET"),
    oidc: {
        issuerUrl: process.env.OIDC_ISSUER_URL || "https://idp.alliancecan.ca",
        clientId: process.env.OIDC_CLIENT_ID || "",
        clientSecret: process.env.OIDC_CLIENT_SECRET || "",
        redirectUri: process.env.OIDC_REDIRECT_URI || "",
        scopes: "openid profile email ca.alliancecan.userinfo",
        get enabled(): boolean {
            return Boolean(this.clientId && this.clientSecret && this.redirectUri);
        },
    },
    token: {
        hmacSecret: env("TOKEN_HMAC_SECRET"),
        storePath: process.env.TOKEN_STORE_PATH || "./token-store.json",
        ttlDays: envInt("TOKEN_TTL_DAYS", 30),
        maxTtlDays: envInt("TOKEN_MAX_TTL_DAYS", 365),
    },
    // Read-only directory lookup for Slurm cluster access.  Anonymous search
    // is sufficient for the three access attributes; a dedicated bind
    // account can be supplied via LDAP_BIND_DN/LDAP_BIND_PASSWORD instead.
    // The directory certificate is system-trusted (Let's Encrypt), so
    // LDAP_CA_CERTS is only needed if that changes.
    ldap: {
        url: (process.env.LDAP_URL || "").trim(),
        baseDn: (process.env.LDAP_BASE_DN || "dc=computecanada,dc=ca").trim(),
        bindDn: (process.env.LDAP_BIND_DN || "").trim(),
        bindPassword: process.env.LDAP_BIND_PASSWORD || "",
        caPath: (process.env.LDAP_CA_CERTS || "").trim(),
        // Optional when LDAP_URL uses an IP address: the TLS certificate is
        // issued to the directory hostname, so SNI/verification needs it.
        tlsServername: (process.env.LDAP_TLS_SERVERNAME || "").trim(),
        timeoutMs: envInt("LDAP_TIMEOUT_MS", 3000),
        cacheTtlMs: envInt("LDAP_CACHE_TTL_MS", 5 * 60 * 1000),
        get enabled(): boolean {
            return this.url !== "" && this.baseDn !== "";
        },
    },
    // Explicit account-disable blocks are driven by LDAP, which has no
    // webhook.  The issuer therefore rechecks users with live tokens (and
    // users it has automatically blocked) on this interval.  Cluster access
    // itself remains enforced per request by the MCP servers; this sweep is
    // what revokes non-cluster tokens and clears the block on restore.
    accountDisable: {
        sweepSeconds: envInt("ACCOUNT_DISABLE_SWEEP_SECONDS", 60),
        sweepConcurrency: envInt("ACCOUNT_DISABLE_SWEEP_CONCURRENCY", 4),
    },
    services: services(),
    // POSIX group whose cn grants Balam access, searched under LDAP_BASE_DN.
    // Only consulted when a service declares slurmCluster "balam".
    // SciNet's group is the default; other deployments set their own.
    balamGroupCn: (process.env.BALAM_GROUP_CN || "lcl_balam").trim(),
    // OIDC groups allowed to use the admin API/UI (lowercased).  Empty
    // disables admin access entirely.
    adminGroups: (process.env.ADMIN_GROUPS || "scinet")
        .split(",")
        .map((g) => g.trim().toLowerCase())
        .filter(Boolean),
    // Ops-maintained admin list on the shared volume (ADMIN_LIST_PATH),
    // OR-ed with adminGroups: anyone listed here is admin even when the IdP
    // does not release a group claim.  Mirrors file-mcp's staff list pattern.
    adminListPath: process.env.ADMIN_LIST_PATH || "/data/admin-users.json",
    production: process.env.NODE_ENV === "production",
};
