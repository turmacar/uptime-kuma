const { describe, test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert");
const crypto = require("crypto");
const http = require("http");
const jwt = require("jsonwebtoken");
const { OIDCHandler } = require("../../server/oidc-handler");

/**
 * Minimal fake identity provider: discovery, JWKS and a token endpoint that checks PKCE.
 */
class FakeProvider {
    keys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    expected = null;
    claims = {};
    signingKey = this.keys.privateKey;
    tokenRequests = 0;

    /**
     * Listen on a random local port.
     * @returns {Promise<void>}
     */
    async start() {
        this.server = http.createServer((req, res) => this.handle(req, res));
        await new Promise((resolve) => this.server.listen(0, "127.0.0.1", resolve));
        this.issuer = `http://127.0.0.1:${this.server.address().port}`;
    }

    /**
     * Close the server.
     * @returns {void}
     */
    stop() {
        this.server.close();
    }

    /**
     * Send a JSON response.
     * @param {object} res Response
     * @param {number} status HTTP status
     * @param {object} body JSON body
     * @returns {void}
     */
    json(res, status, body) {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
    }

    /**
     * Route a request.
     * @param {object} req Request
     * @param {object} res Response
     * @returns {void}
     */
    handle(req, res) {
        if (req.url === "/.well-known/openid-configuration") {
            return this.json(res, 200, {
                issuer: this.issuer,
                authorization_endpoint: `${this.issuer}/authorize`,
                token_endpoint: `${this.issuer}/token`,
                jwks_uri: `${this.issuer}/jwks`,
                response_types_supported: ["code"],
                subject_types_supported: ["public"],
                id_token_signing_alg_values_supported: ["RS256"],
            });
        }
        if (req.url === "/jwks") {
            const jwk = { ...this.keys.publicKey.export({ format: "jwk" }), kid: "k1", use: "sig", alg: "RS256" };
            return this.json(res, 200, { keys: [jwk] });
        }
        if (req.url === "/token" && req.method === "POST") {
            let body = "";
            req.on("data", (c) => (body += c));
            req.on("end", () => {
                this.tokenRequests++;
                const form = new URLSearchParams(body);
                const challenge = crypto
                    .createHash("sha256")
                    .update(form.get("code_verifier") ?? "")
                    .digest("base64url");
                if (form.get("code") !== "good-code" || challenge !== this.expected.challenge) {
                    return this.json(res, 400, { error: "invalid_grant" });
                }
                const now = Math.floor(Date.now() / 1000);
                const idToken = jwt.sign(
                    {
                        iss: this.issuer,
                        aud: "kuma",
                        sub: "user-1",
                        nonce: this.expected.nonce,
                        iat: now,
                        exp: now + 300,
                        email: "me@example.com",
                        email_verified: true,
                        name: "Me",
                        preferred_username: "me",
                        ...this.claims,
                    },
                    this.signingKey,
                    { algorithm: "RS256", keyid: "k1" }
                );
                this.json(res, 200, { access_token: "at", token_type: "Bearer", id_token: idToken });
            });
            return;
        }
        res.writeHead(404);
        res.end();
    }
}

describe("OIDC handler", () => {
    const provider = new FakeProvider();
    let config;
    let handler;

    before(async () => {
        await provider.start();
    });

    after(() => provider.stop());

    beforeEach(() => {
        handler = new OIDCHandler();
        provider.claims = {};
        provider.signingKey = provider.keys.privateKey;
        provider.tokenRequests = 0;
        config = {
            enabled: true,
            clientId: "kuma",
            clientSecret: "secret",
            issuer: provider.issuer,
            redirectUri: "https://uptime.example.com/auth/oidc/callback",
            scopes: ["openid", "profile", "email"],
            requireEmailVerified: false,
        };
    });

    /**
     * Start a login and tell the fake provider what it must see at the token endpoint.
     * @returns {Promise<{url: URL, checks: object}>} Authorization request
     */
    async function begin() {
        const { url, checks } = await handler.createAuthorization(config);
        const parsed = new URL(url);
        provider.expected = {
            nonce: parsed.searchParams.get("nonce"),
            challenge: parsed.searchParams.get("code_challenge"),
        };
        return { url: parsed, checks };
    }

    test("authorization URL carries state, nonce, PKCE and scopes", async () => {
        const { url, checks } = await begin();
        assert.strictEqual(url.origin + url.pathname, `${provider.issuer}/authorize`);
        assert.strictEqual(url.searchParams.get("response_type"), "code");
        assert.strictEqual(url.searchParams.get("client_id"), "kuma");
        assert.strictEqual(url.searchParams.get("redirect_uri"), config.redirectUri);
        assert.strictEqual(url.searchParams.get("scope"), "openid profile email");
        assert.strictEqual(url.searchParams.get("state"), checks.state);
        assert.strictEqual(url.searchParams.get("code_challenge_method"), "S256");
        assert.notStrictEqual(checks.state, checks.nonce);
    });

    test("each login gets fresh checks", async () => {
        const a = await begin();
        const b = await begin();
        assert.notStrictEqual(a.checks.state, b.checks.state);
        assert.notStrictEqual(a.checks.codeVerifier, b.checks.codeVerifier);
    });

    test("valid callback returns the verified identity", async () => {
        const { checks } = await begin();
        const identity = await handler.handleCallback(config, { code: "good-code", state: checks.state }, checks);
        assert.deepStrictEqual(identity, {
            sub: "user-1",
            issuer: provider.issuer,
            email: "me@example.com",
            emailVerified: true,
            name: "Me",
            preferredUsername: "me",
        });
    });

    test("rejects a state mismatch before contacting the token endpoint", async () => {
        const { checks } = await begin();
        await assert.rejects(
            handler.handleCallback(config, { code: "good-code", state: "forged" }, checks),
            (e) => e.code === "invalid_callback"
        );
        assert.strictEqual(provider.tokenRequests, 0);
    });

    test("rejects a missing state", async () => {
        const { checks } = await begin();
        await assert.rejects(
            handler.handleCallback(config, { code: "good-code" }, checks),
            (e) => e.code === "invalid_callback"
        );
    });

    test("rejects an ID token with the wrong nonce", async () => {
        const { checks } = await begin();
        provider.claims = { nonce: "attacker-nonce" };
        await assert.rejects(
            handler.handleCallback(config, { code: "good-code", state: checks.state }, checks),
            (e) => e.code === "invalid_callback"
        );
    });

    test("rejects an ID token signed with another key", async () => {
        const { checks } = await begin();
        provider.signingKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
        await assert.rejects(
            handler.handleCallback(config, { code: "good-code", state: checks.state }, checks),
            (e) => e.code === "invalid_callback"
        );
    });

    test("rejects an expired ID token", async () => {
        const { checks } = await begin();
        const past = Math.floor(Date.now() / 1000) - 3600;
        provider.claims = { iat: past - 300, exp: past };
        await assert.rejects(
            handler.handleCallback(config, { code: "good-code", state: checks.state }, checks),
            (e) => e.code === "invalid_callback"
        );
    });

    test("rejects an ID token from another issuer or for another audience", async () => {
        for (const claims of [{ iss: "https://evil.example.com" }, { aud: "someone-else" }]) {
            const { checks } = await begin();
            provider.claims = claims;
            await assert.rejects(
                handler.handleCallback(config, { code: "good-code", state: checks.state }, checks),
                (e) => e.code === "invalid_callback"
            );
        }
    });

    test("rejects a wrong PKCE verifier", async () => {
        const { checks } = await begin();
        await assert.rejects(
            handler.handleCallback(
                config,
                { code: "good-code", state: checks.state },
                { ...checks, codeVerifier: "x".repeat(64) }
            ),
            (e) => e.code === "invalid_callback"
        );
    });

    test("enforces email_verified only when configured", async () => {
        let { checks } = await begin();
        provider.claims = { email_verified: false };
        const lenient = await handler.handleCallback(config, { code: "good-code", state: checks.state }, checks);
        assert.strictEqual(lenient.emailVerified, false);

        config.requireEmailVerified = true;
        ({ checks } = await begin());
        provider.claims = { email_verified: false };
        await assert.rejects(
            handler.handleCallback(config, { code: "good-code", state: checks.state }, checks),
            (e) => e.code === "email_not_verified"
        );
    });

    test("surfaces a provider error without a token request", async () => {
        const { checks } = await begin();
        await assert.rejects(
            handler.handleCallback(config, { error: "access_denied", state: checks.state }, checks),
            (e) =>
                e.code === "provider_error" &&
                !e.message.includes("access_denied") &&
                e.detail.includes("access_denied")
        );
        assert.strictEqual(provider.tokenRequests, 0);
    });

    test("requires the session checks", async () => {
        await assert.rejects(
            handler.handleCallback(config, { code: "good-code" }, null),
            (e) => e.code === "no_session"
        );
    });

    test("reports an unreachable provider", async () => {
        config.issuer = "http://127.0.0.1:1";
        await assert.rejects(handler.createAuthorization(config), (e) => e.code === "discovery_failed");
    });

    test("caches the client until reset", async () => {
        const first = await handler.getClient(config);
        assert.strictEqual(await handler.getClient(config), first);
        handler.reset();
        assert.notStrictEqual(await handler.getClient(config), first);
    });
});
