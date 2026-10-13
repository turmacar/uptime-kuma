const crypto = require("crypto");
const http = require("http");
const jwt = require("jsonwebtoken");

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
     * Listen on a local port (random unless given).
     * @param {number} port Port to listen on
     * @returns {Promise<void>}
     */
    async start(port = 0) {
        this.server = http.createServer((req, res) => this.handle(req, res));
        await new Promise((resolve) => this.server.listen(port, "127.0.0.1", resolve));
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
        if (req.url.startsWith("/authorize")) {
            // Approve immediately, like a browser session that is already signed in
            const query = new URL(req.url, this.issuer).searchParams;
            this.expected = { nonce: query.get("nonce"), challenge: query.get("code_challenge") };
            const back = new URL(query.get("redirect_uri"));
            back.searchParams.set("code", "good-code");
            back.searchParams.set("state", query.get("state"));
            res.writeHead(302, { location: back.toString() });
            return res.end();
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

module.exports = { FakeProvider };
