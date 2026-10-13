const { describe, test, before, after } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { OIDCHandler } = require("../../server/oidc-handler");

const openssl = spawnSync("openssl", ["version"]);

describe("OIDC TLS validation", { skip: openssl.status !== 0 && "openssl is not available" }, () => {
    let dir;
    let server;
    let issuer;
    let discoveryRequests = 0;

    before(async () => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), "kuma-oidc-tls-"));
        const generated = spawnSync("openssl", [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            path.join(dir, "key.pem"),
            "-out",
            path.join(dir, "cert.pem"),
            "-subj",
            "/CN=localhost",
            "-days",
            "1",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ]);
        assert.strictEqual(generated.status, 0, String(generated.stderr));

        server = https.createServer(
            { key: fs.readFileSync(path.join(dir, "key.pem")), cert: fs.readFileSync(path.join(dir, "cert.pem")) },
            (req, res) => {
                discoveryRequests++;
                res.writeHead(200, { "content-type": "application/json" });
                res.end(
                    JSON.stringify({
                        issuer,
                        authorization_endpoint: `${issuer}/authorize`,
                        token_endpoint: `${issuer}/token`,
                        jwks_uri: `${issuer}/jwks`,
                        response_types_supported: ["code"],
                        subject_types_supported: ["public"],
                        id_token_signing_alg_values_supported: ["RS256"],
                    })
                );
            }
        );
        await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
        issuer = `https://localhost:${server.address().port}`;
    });

    after(() => {
        server.close();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    /**
     * Fetch the discovery document while ignoring the certificate, to prove the server works.
     * @returns {Promise<number>} HTTP status
     */
    function fetchIgnoringCertificate() {
        return new Promise((resolve, reject) => {
            https
                .get(`${issuer}/.well-known/openid-configuration`, { rejectUnauthorized: false }, (res) => {
                    res.resume();
                    resolve(res.statusCode);
                })
                .on("error", reject);
        });
    }

    test("the provider itself answers, so a refusal below is about the certificate", async () => {
        assert.strictEqual(await fetchIgnoringCertificate(), 200);
    });

    test("a login is not started against a provider with an untrusted certificate", async () => {
        const before = discoveryRequests;
        const handler = new OIDCHandler();
        const config = {
            issuer,
            clientId: "kuma",
            clientSecret: "secret",
            redirectUri: "https://uptime.example.com/auth/oidc/callback",
            scopes: ["openid"],
        };

        await assert.rejects(handler.createAuthorization(config), (e) => {
            assert.strictEqual(e.code, "discovery_failed");
            assert.match(e.detail, /self[- ]signed|certificate|unable to verify/i);
            return true;
        });
        assert.strictEqual(discoveryRequests, before, "no HTTP request got through the TLS handshake");
    });

    test("the connection test refuses an untrusted certificate too", async () => {
        await assert.rejects(new OIDCHandler().testConnection(issuer), (e) => e.code === "discovery_failed");
    });
});
