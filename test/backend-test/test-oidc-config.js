const { describe, test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const { Settings } = require("../../server/settings");
const oidcConfig = require("../../server/oidc-config");

const VALID = {
    enabled: true,
    clientId: "kuma",
    clientSecret: "s3cret-value",
    issuer: "https://auth.example.com/application/o/kuma/",
    redirectUri: "https://uptime.example.com/auth/oidc/callback",
    scopes: ["openid", "email"],
};

describe("OIDC config: parsing and validation", () => {
    test("defaults are safe", () => {
        const config = oidcConfig.fromRaw({});
        assert.strictEqual(config.enabled, false);
        assert.strictEqual(config.autoLink, false);
        assert.strictEqual(config.requireEmailVerified, false);
        assert.strictEqual(config.verifyEmailUrl, "");
        assert.deepStrictEqual(config.scopes, ["openid", "profile", "email"]);
    });

    test("the email verification link is optional and must be http(s)", () => {
        assert.deepStrictEqual(oidcConfig.validate({ ...VALID, verifyEmailUrl: "" }), []);
        assert.deepStrictEqual(
            oidcConfig.validate({ ...VALID, verifyEmailUrl: "https://auth.example.com/if/user/" }),
            []
        );
        for (const url of ["javascript:alert(1)", "data:text/html,x", "ftp://example.com", "not a url"]) {
            const errors = oidcConfig.validate({ ...VALID, verifyEmailUrl: url });
            assert.deepStrictEqual(errors, ["Email verification link must be an http(s) URL"], url);
        }
    });

    test("scopes always include openid and are de-duplicated", () => {
        assert.deepStrictEqual(oidcConfig.parseScopes("email, profile,email"), ["openid", "email", "profile"]);
        assert.deepStrictEqual(oidcConfig.parseScopes(["openid", "groups"]), ["openid", "groups"]);
    });

    test("valid config has no errors", () => {
        assert.deepStrictEqual(oidcConfig.validate(VALID), []);
    });

    test("reports each missing field", () => {
        const errors = oidcConfig.validate(oidcConfig.fromRaw({}));
        assert.strictEqual(errors.length, 4);
    });

    test("issuer must use https except for localhost", () => {
        assert.ok(oidcConfig.validate({ ...VALID, issuer: "http://auth.example.com" }).length > 0);
        assert.deepStrictEqual(oidcConfig.validate({ ...VALID, issuer: "http://localhost:9000" }), []);
        assert.ok(oidcConfig.validate({ ...VALID, issuer: "javascript:alert(1)" }).length > 0);
        assert.ok(oidcConfig.validate({ ...VALID, redirectUri: "not a url" }).length > 0);
    });

    test("sanitize never includes the secret", () => {
        const out = oidcConfig.sanitize(VALID);
        assert.ok(!JSON.stringify(out).includes(VALID.clientSecret));
        assert.strictEqual(out.hasClientSecret, true);
    });
});

describe("OIDC config: load and save", () => {
    const realGet = Settings.getSettings;
    const realSet = Settings.setSettings;
    let store;

    beforeEach(() => {
        store = {};
        Settings.getSettings = async () => ({ ...store });
        Settings.setSettings = async (type, data) => {
            assert.strictEqual(type, oidcConfig.SETTINGS_TYPE);
            Object.assign(store, data);
        };
    });

    afterEach(() => {
        Settings.getSettings = realGet;
        Settings.setSettings = realSet;
    });

    test("nothing stored means disabled", async () => {
        const { config } = await oidcConfig.load();
        assert.strictEqual(config.enabled, false);
    });

    test("save then load round trips", async () => {
        await oidcConfig.save(VALID);

        const { config, errors } = await oidcConfig.load();
        assert.deepStrictEqual(errors, []);
        assert.strictEqual(config.enabled, true);
        assert.strictEqual(config.clientSecret, VALID.clientSecret);
    });

    test("the email verification link is saved, kept when omitted, and an invalid one blocks enabling", async () => {
        const link = "https://auth.example.com/if/user/";
        await oidcConfig.save({ ...VALID, verifyEmailUrl: link });
        assert.strictEqual((await oidcConfig.load()).config.verifyEmailUrl, link);

        await oidcConfig.save({ clientId: "renamed" });
        assert.strictEqual((await oidcConfig.load()).config.verifyEmailUrl, link);

        await assert.rejects(oidcConfig.save({ verifyEmailUrl: "javascript:alert(1)" }), /Email verification link/);
        assert.strictEqual((await oidcConfig.load()).config.verifyEmailUrl, link);
    });

    test("save without a secret keeps the stored one", async () => {
        await oidcConfig.save(VALID);
        await oidcConfig.save({ clientId: "renamed", clientSecret: "" });

        const { config } = await oidcConfig.load();
        assert.strictEqual(config.clientId, "renamed");
        assert.strictEqual(config.clientSecret, VALID.clientSecret);
        assert.strictEqual(config.enabled, true);
    });

    test("enabling an invalid config is rejected and stores nothing", async () => {
        await assert.rejects(oidcConfig.save({ ...VALID, issuer: "" }), /Invalid OIDC configuration/);
        assert.deepStrictEqual(store, {});
    });

    test("a partial config can be saved while disabled", async () => {
        await oidcConfig.save({ enabled: false, clientId: "kuma" });
        const { config, errors } = await oidcConfig.load();
        assert.strictEqual(config.enabled, false);
        assert.ok(errors.length > 0);
    });

    test("an enabled but invalid stored config is forced off", async () => {
        store = { oidc_enabled: true, oidc_client_id: "kuma" };
        const { config, errors } = await oidcConfig.load();
        assert.strictEqual(config.enabled, false);
        assert.ok(errors.length > 0);
    });
});
