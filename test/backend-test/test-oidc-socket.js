const { describe, test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert");
const { FakeProvider } = require("./helpers/fake-oidc-provider");
const { setupTestDatabase } = require("./helpers/test-database");

describe("OIDC settings socket events", () => {
    const provider = new FakeProvider();
    const PASSWORD = "correct horse";
    let db;
    let R;
    let oidcConfig;
    let oidcHandler;
    let passwordHash;
    let socket;
    let resets;
    let realReset;

    /**
     * Minimal stand-in for a socket.io socket that records handlers.
     * @returns {object} Socket with `call(event, ...args)` returning the callback result
     */
    function makeSocket() {
        const handlers = {};
        return {
            userID: undefined,
            on: (event, fn) => (handlers[event] = fn),
            call: (event, ...args) => new Promise((resolve) => handlers[event](...args, resolve)),
        };
    }

    /**
     * @param {object} extra Overrides
     * @returns {object} A complete, valid settings payload
     */
    function validSettings(extra = {}) {
        return {
            enabled: true,
            clientId: "kuma",
            clientSecret: "secret",
            issuer: provider.issuer,
            redirectUri: "http://localhost:3001/auth/oidc/callback",
            scopes: ["openid", "email"],
            ...extra,
        };
    }

    /**
     * Insert a user and log the socket in as that user.
     * @param {string} username Username
     * @param {object} extra Extra column values
     * @returns {Promise<object>} User bean
     */
    async function loginAs(username, extra = {}) {
        const bean = R.dispense("user");
        bean.username = username;
        bean.password = await passwordHash.generate(PASSWORD);
        Object.assign(bean, extra);
        const id = await R.store(bean);
        socket.userID = id;
        return await R.findOne("user", " id = ? ", [id]);
    }

    before(async () => {
        await provider.start();
        db = await setupTestDatabase();
        R = db.R;

        oidcConfig = require("../../server/oidc-config");
        ({ oidcHandler } = require("../../server/oidc-handler"));
        passwordHash = require("../../server/password-hash");
        const { oidcSocketHandler } = require("../../server/socket-handlers/oidc-socket-handler");

        socket = makeSocket();
        oidcSocketHandler(socket);

        realReset = oidcHandler.reset;
        oidcHandler.reset = () => resets++;
    });

    after(async () => {
        oidcHandler.reset = realReset;
        provider.stop();
        await db.cleanup();
    });

    beforeEach(async () => {
        resets = 0;
        socket.userID = undefined;
        await R.exec("DELETE FROM `user`");
        await R.exec("DELETE FROM setting WHERE type = 'oidc'");
    });

    test("every event needs a logged-in user", async () => {
        for (const [event, args] of [
            ["getOIDCSettings", []],
            ["setOIDCSettings", [validSettings(), PASSWORD]],
            ["testOIDCConnection", [provider.issuer]],
            ["getOIDCInfo", []],
            ["unlinkOIDC", [PASSWORD]],
        ]) {
            const res = await socket.call(event, ...args);
            assert.deepStrictEqual([res.ok, res.msg], [false, "You are not logged in."], event);
        }
        assert.strictEqual(resets, 0);
    });

    test("getOIDCSettings shows defaults and never returns the secret", async () => {
        await loginAs("alice");
        const empty = await socket.call("getOIDCSettings");
        assert.strictEqual(empty.ok, true);
        assert.strictEqual(empty.config.enabled, false);
        assert.strictEqual(empty.config.hasClientSecret, false);
        assert.ok(empty.errors.length > 0);

        await socket.call("setOIDCSettings", validSettings(), PASSWORD);
        const res = await socket.call("getOIDCSettings");
        assert.strictEqual(res.config.hasClientSecret, true);
        assert.strictEqual(res.config.clientId, "kuma");
        assert.deepStrictEqual(res.errors, []);
        assert.ok(!JSON.stringify(res).includes("secret"));
    });

    test("enabling needs the current password", async () => {
        await loginAs("alice");

        for (const password of ["wrong", undefined, 1234, ""]) {
            const res = await socket.call("setOIDCSettings", validSettings(), password);
            assert.strictEqual(res.ok, false, String(password));
        }
        assert.strictEqual((await oidcConfig.load()).config.enabled, false);
        assert.strictEqual(resets, 0);

        const res = await socket.call("setOIDCSettings", validSettings(), PASSWORD);
        assert.strictEqual(res.ok, true);
        assert.strictEqual(res.msg, "Saved.");
        assert.strictEqual((await oidcConfig.load()).config.enabled, true);
        assert.strictEqual(resets, 1);
    });

    test("changing the settings while enabled needs the password too", async () => {
        await loginAs("alice");
        await socket.call("setOIDCSettings", validSettings(), PASSWORD);

        const res = await socket.call(
            "setOIDCSettings",
            validSettings({ issuer: "https://evil.example.com" }),
            "wrong"
        );
        assert.strictEqual(res.ok, false);
        assert.strictEqual((await oidcConfig.load()).config.issuer, provider.issuer);

        const noPassword = await socket.call("setOIDCSettings", validSettings({ autoLink: true }), undefined);
        assert.strictEqual(noPassword.ok, false);
        assert.strictEqual((await oidcConfig.load()).config.autoLink, false);
    });

    test("disabling needs no password and keeps the other settings", async () => {
        await loginAs("alice");
        await socket.call("setOIDCSettings", validSettings(), PASSWORD);

        const res = await socket.call("setOIDCSettings", { enabled: false }, undefined);
        assert.strictEqual(res.ok, true);

        const { config } = await oidcConfig.load();
        assert.strictEqual(config.enabled, false);
        assert.strictEqual(config.clientId, "kuma");
        assert.strictEqual(config.clientSecret, "secret");
        assert.strictEqual(resets, 2);
    });

    test("a partial config can be saved while disabled", async () => {
        await loginAs("alice");
        const res = await socket.call("setOIDCSettings", { enabled: false, clientId: "kuma" }, undefined);
        assert.strictEqual(res.ok, true);
        assert.strictEqual((await oidcConfig.load()).config.clientId, "kuma");
    });

    test("an invalid config cannot be enabled, even with the right password", async () => {
        await loginAs("alice");
        const res = await socket.call("setOIDCSettings", validSettings({ issuer: "not a url" }), PASSWORD);
        assert.strictEqual(res.ok, false);
        assert.match(res.msg, /Invalid OIDC configuration/);
        assert.strictEqual((await oidcConfig.load()).config.clientId, "");
    });

    test("an empty client secret keeps the stored one", async () => {
        await loginAs("alice");
        await socket.call("setOIDCSettings", validSettings(), PASSWORD);
        const res = await socket.call(
            "setOIDCSettings",
            validSettings({ clientSecret: "", clientId: "renamed" }),
            PASSWORD
        );

        assert.strictEqual(res.ok, true);
        const { config } = await oidcConfig.load();
        assert.strictEqual(config.clientId, "renamed");
        assert.strictEqual(config.clientSecret, "secret");
    });

    test("an account without a password cannot enable OIDC", async () => {
        await loginAs("alice", { password: null });
        const res = await socket.call("setOIDCSettings", validSettings(), PASSWORD);
        assert.strictEqual(res.ok, false);
        assert.match(res.msg, /Set a password/);
        assert.strictEqual((await oidcConfig.load()).config.enabled, false);
    });

    test("malformed payloads are rejected before anything is stored", async () => {
        await loginAs("alice");
        const bad = [
            null,
            "enabled",
            [],
            {},
            { enabled: "true" },
            { enabled: false, clientId: 5 },
            { enabled: false, autoLink: "yes" },
            { enabled: false, scopes: "openid" },
            { enabled: false, scopes: [1] },
            { enabled: false, verifyEmailUrl: 5 },
        ];
        for (const payload of bad) {
            const res = await socket.call("setOIDCSettings", payload, PASSWORD);
            assert.deepStrictEqual([res.ok, res.msg], [false, "Invalid data"], JSON.stringify(payload));
        }
        assert.strictEqual(resets, 0);
        assert.strictEqual((await R.getAll("SELECT key FROM setting WHERE type = 'oidc'")).length, 0);
    });

    test("the email verification link is saved and returned, and a non-http(s) one is refused", async () => {
        await loginAs("alice");
        const link = "https://auth.example.com/if/user/";

        const saved = await socket.call("setOIDCSettings", validSettings({ verifyEmailUrl: link }), PASSWORD);
        assert.strictEqual(saved.ok, true);
        assert.strictEqual((await socket.call("getOIDCSettings")).config.verifyEmailUrl, link);

        const bad = await socket.call(
            "setOIDCSettings",
            validSettings({ verifyEmailUrl: "javascript:alert(1)" }),
            PASSWORD
        );
        assert.strictEqual(bad.ok, false);
        assert.match(bad.msg, /Email verification link must be an http\(s\) URL/);
        assert.strictEqual((await socket.call("getOIDCSettings")).config.verifyEmailUrl, link);
    });

    test("unknown fields in the payload are ignored", async () => {
        await loginAs("alice");
        const res = await socket.call("setOIDCSettings", { enabled: false, evil: "x", oidc_enabled: true }, undefined);
        assert.strictEqual(res.ok, true);
        assert.strictEqual((await R.getAll("SELECT key FROM setting WHERE key = 'evil'")).length, 0);
        assert.strictEqual((await oidcConfig.load()).config.enabled, false);
    });

    test("testOIDCConnection reports what the provider offers and stores nothing", async () => {
        await loginAs("alice");
        const res = await socket.call("testOIDCConnection", provider.issuer);

        assert.strictEqual(res.ok, true);
        assert.strictEqual(res.issuer, provider.issuer);
        assert.strictEqual(res.authorizationEndpoint, `${provider.issuer}/authorize`);
        assert.deepStrictEqual(res.warnings, []);
        assert.strictEqual((await R.getAll("SELECT key FROM setting WHERE type = 'oidc'")).length, 0);
    });

    test("testOIDCConnection warns when the provider reports a different issuer", async () => {
        await loginAs("alice");
        const res = await socket.call("testOIDCConnection", provider.issuer + "/");
        assert.strictEqual(res.ok, true);
        assert.deepStrictEqual(res.warnings, ["issuer_mismatch"]);
    });

    test("testOIDCConnection rejects bad input and unreachable providers", async () => {
        await loginAs("alice");
        for (const issuer of [undefined, "", "not a url", "ftp://example.com", "http://auth.example.com"]) {
            const res = await socket.call("testOIDCConnection", issuer);
            assert.strictEqual(res.ok, false, String(issuer));
        }
        const down = await socket.call("testOIDCConnection", "http://127.0.0.1:1");
        assert.strictEqual(down.ok, false);
        assert.match(down.msg, /Could not reach/);
    });

    test("getOIDCInfo reports the link status of the logged-in user", async () => {
        await loginAs("alice");
        assert.deepStrictEqual((await socket.call("getOIDCInfo")).info, {
            linked: false,
            sub: null,
            issuer: null,
            lastLogin: null,
        });

        await R.exec("UPDATE `user` SET oidc_sub = 's1', oidc_issuer = 'https://auth.example.com' WHERE id = ?", [
            socket.userID,
        ]);
        const { info } = await socket.call("getOIDCInfo");
        assert.strictEqual(info.linked, true);
        assert.strictEqual(info.sub, "s1");
    });

    test("unlinkOIDC needs the password, clears the link and leaves other users alone", async () => {
        const alice = await loginAs("alice", { oidc_sub: "s1", oidc_issuer: "https://auth.example.com" });
        const bob = R.dispense("user");
        bob.username = "bob";
        bob.password = "hash";
        bob.oidc_sub = "s2";
        bob.oidc_issuer = "https://auth.example.com";
        await R.store(bob);

        const denied = await socket.call("unlinkOIDC", "wrong");
        assert.strictEqual(denied.ok, false);
        assert.strictEqual((await R.findOne("user", " id = ? ", [alice.id])).oidc_sub, "s1");

        const res = await socket.call("unlinkOIDC", PASSWORD);
        assert.strictEqual(res.ok, true);
        assert.strictEqual((await R.findOne("user", " id = ? ", [alice.id])).oidc_sub, null);
        assert.strictEqual((await R.findOne("user", " username = 'bob' ")).oidc_sub, "s2");
    });
});
