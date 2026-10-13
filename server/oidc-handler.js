// OIDC: authorization code flow (PKCE, state, nonce) against a single issuer via openid-client.
const oidc = require("openid-client");
const { R } = require("redbean-node");
const { log } = require("../src/util");
const User = require("./model/user");

/**
 * Error with a message that is safe to show to the user.
 * Details for the server log go in `detail`.
 */
class OIDCError extends Error {
    /**
     * @param {string} code Machine readable code
     * @param {string} message User facing message
     * @param {?string} detail Extra detail for logs only
     */
    constructor(code, message, detail = null) {
        super(message);
        this.name = "OIDCError";
        this.code = code;
        this.detail = detail;
    }
}

class OIDCHandler {
    /** @type {?{key: string, client: object}} */
    clientCache = null;

    /**
     * Drop the cached issuer/client, e.g. after the settings changed.
     * @returns {void}
     */
    reset() {
        this.clientCache = null;
    }

    /**
     * Get an openid-client Client for the config, running discovery on first use.
     * @param {object} config Config from oidc-config load()
     * @returns {Promise<object>} openid-client Client
     */
    async getClient(config) {
        const key = JSON.stringify([config.issuer, config.clientId, config.clientSecret, config.redirectUri]);
        if (this.clientCache?.key === key) {
            return this.clientCache.client;
        }

        let issuer;
        try {
            issuer = await oidc.Issuer.discover(config.issuer);
        } catch (e) {
            throw new OIDCError("discovery_failed", "Could not reach the identity provider", e.message);
        }

        const client = new issuer.Client({
            client_id: config.clientId,
            client_secret: config.clientSecret,
            redirect_uris: [config.redirectUri],
            response_types: ["code"],
        });
        client[oidc.custom.http_options] = () => ({ timeout: 10000 });
        client[oidc.custom.clock_tolerance] = 5;

        this.clientCache = { key, client };
        return client;
    }

    /**
     * Start a login. The caller must keep `checks` server side (session) until the callback.
     * @param {object} config Config from oidc-config load()
     * @returns {Promise<{url: string, checks: {state: string, nonce: string, codeVerifier: string}}>} Authorization URL and values to verify in the callback
     */
    async createAuthorization(config) {
        const client = await this.getClient(config);
        const checks = {
            state: oidc.generators.state(),
            nonce: oidc.generators.nonce(),
            codeVerifier: oidc.generators.codeVerifier(),
        };
        const url = client.authorizationUrl({
            scope: config.scopes.join(" "),
            redirect_uri: config.redirectUri,
            state: checks.state,
            nonce: checks.nonce,
            code_challenge: oidc.generators.codeChallenge(checks.codeVerifier),
            code_challenge_method: "S256",
        });
        return { url, checks };
    }

    /**
     * Finish a login: validates state, exchanges the code, and verifies the ID token
     * (signature, issuer, audience, expiry, nonce).
     * @param {object} config Config from oidc-config load()
     * @param {object} query Query parameters of the callback request
     * @param {{state: string, nonce: string, codeVerifier: string}} checks Values from createAuthorization()
     * @returns {Promise<{sub: string, issuer: string, email: ?string, emailVerified: boolean, name: ?string, preferredUsername: ?string}>} Verified identity
     * @throws {OIDCError} On any failure
     */
    async handleCallback(config, query, checks) {
        if (!checks?.state || !checks?.nonce || !checks?.codeVerifier) {
            throw new OIDCError("no_session", "Login session expired, please try again");
        }

        const client = await this.getClient(config);
        const params = client.callbackParams({ method: "GET", url: "/?" + new URLSearchParams(query).toString() });

        if (params.error) {
            throw new OIDCError(
                "provider_error",
                "The identity provider rejected the login",
                `${params.error}: ${params.error_description ?? ""}`
            );
        }

        let tokenSet;
        try {
            tokenSet = await client.callback(config.redirectUri, params, {
                state: checks.state,
                nonce: checks.nonce,
                code_verifier: checks.codeVerifier,
                response_type: "code",
            });
        } catch (e) {
            throw new OIDCError("invalid_callback", "Authentication failed, please try again", e.message);
        }

        const claims = tokenSet.claims();

        if (!claims.sub) {
            throw new OIDCError("no_sub", "Authentication failed, please try again", "ID token has no sub claim");
        }

        const emailVerified = claims.email_verified === true;
        if (config.requireEmailVerified && !emailVerified) {
            throw new OIDCError("email_not_verified", "Your email address is not verified at the identity provider");
        }

        return {
            sub: claims.sub,
            issuer: claims.iss,
            email: claims.email ?? null,
            emailVerified,
            name: claims.name ?? null,
            preferredUsername: claims.preferred_username ?? null,
        };
    }

    /**
     * Run discovery against an issuer URL and report what the provider offers. Stores nothing.
     * @param {string} issuerUrl Issuer URL to check
     * @returns {Promise<{issuer: string, authorizationEndpoint: ?string, tokenEndpoint: ?string, warnings: string[]}>} Provider summary; `warnings` holds codes such as `issuer_mismatch`
     * @throws {OIDCError} If discovery fails
     */
    async testConnection(issuerUrl) {
        let issuer;
        try {
            issuer = await oidc.Issuer.discover(issuerUrl);
        } catch (e) {
            throw new OIDCError("discovery_failed", "Could not reach the identity provider", e.message);
        }

        const metadata = issuer.metadata;
        const warnings = [];
        if (metadata.issuer !== issuerUrl) {
            warnings.push("issuer_mismatch");
        }
        if (metadata.grant_types_supported && !metadata.grant_types_supported.includes("authorization_code")) {
            warnings.push("authorization_code_not_supported");
        }
        if (metadata.code_challenge_methods_supported && !metadata.code_challenge_methods_supported.includes("S256")) {
            warnings.push("pkce_not_supported");
        }

        return {
            issuer: metadata.issuer,
            authorizationEndpoint: metadata.authorization_endpoint ?? null,
            tokenEndpoint: metadata.token_endpoint ?? null,
            warnings,
        };
    }

    /**
     * Find the Kuma user for a verified identity.
     * 1. An active user already linked to the identity.
     * 2. If `autoLink` is on, the local user whose username equals `preferred_username`; the identity is linked to it.
     * Accounts are never created, and an account that is already linked or has no password is never linked.
     * @param {object} config Config from oidc-config load()
     * @param {{sub: string, issuer: string, preferredUsername: ?string}} identity Result of handleCallback()
     * @returns {Promise<object>} The user
     * @throws {OIDCError} If no account can be used for the identity
     */
    async resolveUser(config, identity) {
        const linked = await User.findByOIDC(identity.sub, identity.issuer);
        if (linked) {
            return linked;
        }

        const username = identity.preferredUsername?.trim();
        if (config.autoLink && username) {
            const user = await R.findOne("user", " TRIM(username) = ? AND active = 1 ", [username]);

            // Exact match only: MariaDB collations are case-insensitive
            if (user && user.username.trim() === username) {
                if (user.oidc_sub) {
                    throw new OIDCError(
                        "already_linked",
                        "This account is linked to a different identity",
                        `user=${user.username} sub=${identity.sub}`
                    );
                }
                if (!user.password) {
                    throw new OIDCError(
                        "password_required",
                        "Set a password for this account before linking it",
                        `user=${user.username}`
                    );
                }

                await user.linkOIDC(identity.sub, identity.issuer);
                log.info("oidc", `Linked identity ${identity.sub} to user ${user.username}`);
                return user;
            }
        }

        throw new OIDCError(
            "no_account",
            "No account is linked to this identity, contact the administrator",
            `sub=${identity.sub}`
        );
    }
}

module.exports = {
    OIDCError,
    OIDCHandler,
    oidcHandler: new OIDCHandler(),
};
