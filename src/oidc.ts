import {
    ClientSecretBasic,
    authorizationCodeGrant,
    buildAuthorizationUrl,
    discovery,
    fetchUserInfo,
    randomNonce,
    randomState,
    type Configuration,
} from "openid-client";
import { config } from "./config";
import { deriveGroups } from "./groups";
import { log } from "./log";

// Alliance IAM (idp.alliancecan.ca) is a Shibboleth OIDC provider.  These
// conventions are the ones already validated in production by the chat bot:
//
//   * issuer root is https://idp.alliancecan.ca (NOT /idp) -- never override
//     it or ID-token validation fails with an issuer mismatch.
//   * PKCE is NOT used: the provider does not publish
//     code_challenge_methods_supported and the middle-ware team advises
//     against requiring it.  We are a confidential client authenticating
//     with client_secret_basic.
//   * profile/email attributes (preferred_username, ...) come from the
//     UserInfo endpoint, gated by the ca.alliancecan.userinfo scope.

export type OidcUser = {
    sub: string;
    username: string;
    name?: string;
    email?: string;
    // OIDC standard `locale` claim (e.g. "fr", "fr-CA", "fr_CA"), when the
    // IdP releases it.  Seeds the UI language on login, exactly as the
    // trillium-chatbot consumes it.  Absent/empty means "didn't get one".
    locale?: string;
    groups?: string[];
};

export type OidcAuthState = {
    nonce: string;
    state: string;
    // Set for a passive `prompt=none` attempt.  A failure must fall back to
    // the normal signed-out page instead of surfacing an OIDC error.
    silent?: boolean;
};

const configs = new Map<string, Configuration>();

async function getConfig(): Promise<Configuration> {
    const cached = configs.get(config.oidc.issuerUrl);
    if (cached) return cached;

    const newConfig = await discovery(
        new URL(config.oidc.issuerUrl),
        config.oidc.clientId,
        config.oidc.clientSecret,
        ClientSecretBasic(config.oidc.clientSecret),
    );
    configs.set(config.oidc.issuerUrl, newConfig);
    return newConfig;
}

// Pending authorization requests, keyed by state. Kept in-process: a lost
// entry after a restart simply forces a re-login, which is harmless.
const pending = new Map<string, OidcAuthState>();

export async function buildAuthUrl(options: { silent?: boolean } = {}): Promise<string> {
    const c = await getConfig();
    const state = randomState();
    const nonce = randomNonce();

    const params: Record<string, string> = {
        scope: config.oidc.scopes,
        state,
        nonce,
        redirect_uri: config.oidc.redirectUri,
    };
    if (options.silent) {
        // Ask the IdP to reuse its existing browser session without showing
        // an interaction.  If there is no usable session, the IdP returns
        // `login_required`/`interaction_required` and the caller falls back
        // to the signed-out page.
        params.prompt = "none";
    }

    const url = buildAuthorizationUrl(c, params);
    pending.set(state, { state, nonce, silent: options.silent === true });
    return url.href;
}

export function isSilentAuthState(state: string): boolean {
    return pending.get(state)?.silent === true;
}

export function discardAuthState(state: string): void {
    pending.delete(state);
}

export async function handleCallback(currentUrl: URL): Promise<OidcUser> {
    const c = await getConfig();

    const state = currentUrl.searchParams.get("state") || "";
    const stored = pending.get(state);
    if (!stored) {
        throw new Error("OIDC callback without a pending authorization request");
    }
    pending.delete(state);

    const tokenResponse = await authorizationCodeGrant(c, currentUrl, {
        expectedState: stored.state,
        expectedNonce: stored.nonce,
    });
    const claims = tokenResponse.claims();

    // The ID token carries authentication-time claims; profile/email
    // attributes come from UserInfo, with the sub verified to match.
    let userinfo: Record<string, any> = {};
    try {
        userinfo = (await fetchUserInfo(c, tokenResponse.access_token, claims!.sub)) as Record<string, any>;
    } catch (e) {
        log.error("UserInfo lookup failed:", e);
    }

    const username = userinfo.preferred_username || (claims as any).preferred_username || claims!.sub || "";

    // Log which claims the IdP actually released, so we can confirm the
    // `locale` claim (UI-language seeding) and `groups` (staff checks) are
    // part of the release policy for this client.  Mirrors the chatbot's
    // "oidc userinfo received" log.
    log.log("oidc userinfo received", {
        claim_keys: Object.keys(userinfo || {}).sort(),
        preferred_username: username,
    });

    // Group membership for the MCP servers' staff exception.  Fold the
    // IdP's ccServiceAccess staff values into the "cc-staff" group (the
    // IdP releases no groups/roles claim); see groups.ts.
    const groups = deriveGroups(userinfo, claims);

    return {
        sub: claims!.sub,
        username,
        name: userinfo.name || (claims as any).name,
        email: userinfo.email || (claims as any).email,
        locale: userinfo.locale || (claims as any).locale,
        groups,
    };
}
