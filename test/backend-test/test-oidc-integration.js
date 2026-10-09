const { describe, test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const express = require("express");
const dayjs = require("dayjs");
const { FakeProvider } = require("./helpers/fake-oidc-provider");

dayjs.extend(require("dayjs/plugin/utc"));

/**
 * Whole OIDC login against real code: config in SQLite, router, handler, user lookup and ticket redemption.
 * Only the identity provider is fake.
 */
describe("OIDC integration", () => {
    const provider = new FakeProvider();
    let R;
    let oidcConfig;
    let passwordHash;
    let login;
    let redeemOIDCTicket;
    let createOIDCRouter;
    let tickets;
    let tmpDir;
    let httpServer;
    let base;

    /**
     * Save the OIDC settings through the real config module.
     * @param {object} extra Overrides
     * @returns {Promise<void>}
     */
    async function configure(extra = {}) {
        await oidcConfig.save({
            enabled: true,
            clientId: "kuma",
            clientSecret: "secret",
            issuer: provider.issuer,
            redirectUri: "http://localhost:3001/auth/oidc/callback",
            autoLink: false,
            ...extra,
        });
    }

    /**
     * Insert a user.
     * @param {string} username Username
     * @param {object} extra Extra column values
     * @returns {Promise<object>} User bean
     */
    async function addUser(username, extra = {}) {
        const bean = R.dispense("user");
        bean.username = username;
        bean.password = await passwordHash.generate("correct horse");
        Object.assign(bean, extra);
        const id = await R.store(bean);
        return await R.findOne("user", " id = ? ", [id]);
    }

    /**
     * GET without following redirects.
     * @param {string} urlPath Path and query
     * @param {?string} cookie Cookie header value
     * @returns {Promise<Response>} Response
     */
    function get(urlPath, cookie = null) {
        return fetch(base + urlPath, { redirect: "manual", headers: cookie ? { cookie } : {} });
    }

    /**
     * Run the browser side of a login and return the fragment of the final redirect.
     * @returns {Promise<URLSearchParams>} `ticket` or `error`
     */
    async function browserLogin() {
        const start = await get("/auth/oidc/login");
        assert.strictEqual(start.status, 302);
        const url = new URL(start.headers.get("location"));
        provider.expected = {
            nonce: url.searchParams.get("nonce"),
            challenge: url.searchParams.get("code_challenge"),
        };
        const cookie = start.headers.getSetCookie()[0].split(";")[0];

        const end = await get(`/auth/oidc/callback?code=good-code&state=${url.searchParams.get("state")}`, cookie);
        assert.strictEqual(end.status, 302);
        return new URLSearchParams(end.headers.get("location").split("#")[1]);
    }

    before(async () => {
        await provider.start();

        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "kuma-oidc-int-"));
        const Dialect = require("knex/lib/dialects/sqlite3/index.js");
        Dialect.prototype._driver = () => require("@louislam/sqlite3");
        const db = require("knex")({
            client: Dialect,
            connection: { filename: path.join(tmpDir, "test.db") },
            useNullAsDefault: true,
        });

        ({ R } = require("redbean-node"));
        R.setup(db);
        await require("../../db/knex_init_db.js").createTables();
        await R.knex.migrate.latest({ directory: path.join(__dirname, "../../db/knex_migrations") });
        await R.autoloadModels(path.join(__dirname, "../../server/model"));

        oidcConfig = require("../../server/oidc-config");
        passwordHash = require("../../server/password-hash");
        ({ login } = require("../../server/auth"));
        const { oidcTickets } = require("../../server/oidc-store");
        ({ createOIDCRouter, redeemOIDCTicket } = require("../../server/routers/oidc-router"));

        tickets = oidcTickets;
        const app = express();
        app.use(createOIDCRouter({ limiter: { pass: async () => true } }));
        await new Promise((resolve) => {
            httpServer = app.listen(0, "127.0.0.1", resolve);
        });
        base = `http://127.0.0.1:${httpServer.address().port}`;
    });

    after(async () => {
        httpServer.close();
        provider.stop();
        await R.knex.destroy();
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    beforeEach(async () => {
        provider.claims = {};
        provider.tokenRequests = 0;
        tickets.entries.clear();
        await R.exec("DELETE FROM `user`");
        await R.exec("DELETE FROM setting WHERE type = 'oidc'");
        await configure();
    });

    test("is off until configured and enabled", async () => {
        await R.exec("DELETE FROM setting WHERE type = 'oidc'");
        assert.strictEqual((await get("/auth/oidc/login")).status, 404);

        await configure({ enabled: false });
        assert.strictEqual((await get("/auth/oidc/login")).status, 404);
    });

    test("an invalid saved config keeps OIDC off", async () => {
        await R.exec("UPDATE setting SET value = '\"\"' WHERE `key` = 'oidc_client_secret'");
        assert.strictEqual((await get("/auth/oidc/login")).status, 404);
    });

    test("a linked user logs in and the ticket resolves to that user", async () => {
        const alice = await addUser("alice", { oidc_sub: "user-1", oidc_issuer: provider.issuer });

        const result = await browserLogin();
        assert.strictEqual(result.get("error"), null);

        const user = await redeemOIDCTicket(result.get("ticket"));
        assert.strictEqual(user.id, alice.id);
        await user.recordOIDCLogin();
        assert.ok((await R.findOne("user", " id = ? ", [alice.id])).last_oidc_login);

        assert.strictEqual(await redeemOIDCTicket(result.get("ticket")), null);
    });

    test("an unlinked user is linked by username once, when autoLink is on", async () => {
        await configure({ autoLink: true });
        provider.claims = { preferred_username: "alice" };
        const alice = await addUser("alice");

        const first = await browserLogin();
        assert.strictEqual((await redeemOIDCTicket(first.get("ticket"))).id, alice.id);

        const stored = await R.findOne("user", " id = ? ", [alice.id]);
        assert.strictEqual(stored.oidc_sub, "user-1");
        assert.strictEqual(stored.oidc_issuer, provider.issuer);

        // Auto-link off again: the stored link is enough
        await configure({ autoLink: false });
        const second = await browserLogin();
        assert.strictEqual((await redeemOIDCTicket(second.get("ticket"))).id, alice.id);
    });

    test("an unlinked user cannot log in while autoLink is off", async () => {
        provider.claims = { preferred_username: "alice" };
        await addUser("alice");

        const result = await browserLogin();
        assert.strictEqual(result.get("error"), "no_account");
        assert.strictEqual(result.get("ticket"), null);
        assert.strictEqual(tickets.entries.size, 0);
    });

    test("another identity cannot take over a linked account by username", async () => {
        await configure({ autoLink: true });
        provider.claims = { sub: "someone-else", preferred_username: "alice" };
        await addUser("alice", { oidc_sub: "user-1", oidc_issuer: provider.issuer });

        const result = await browserLogin();
        assert.strictEqual(result.get("error"), "already_linked");
        assert.strictEqual((await R.findOne("user", " username = 'alice' ")).oidc_sub, "user-1");
    });

    test("a ticket stops working once OIDC is disabled or the user is deactivated", async () => {
        const alice = await addUser("alice", { oidc_sub: "user-1", oidc_issuer: provider.issuer });

        const control = await browserLogin();
        assert.strictEqual((await redeemOIDCTicket(control.get("ticket"))).id, alice.id);

        const disabled = await browserLogin();
        await configure({ enabled: false });
        assert.strictEqual(await redeemOIDCTicket(disabled.get("ticket")), null);

        await configure({ enabled: true });
        const deactivated = await browserLogin();
        await R.exec("UPDATE `user` SET active = 0 WHERE id = ? ", [alice.id]);
        assert.strictEqual(await redeemOIDCTicket(deactivated.get("ticket")), null);
    });

    test("native password login is unaffected by OIDC, linked or not", async () => {
        await addUser("plain");
        await addUser("linked", { oidc_sub: "user-1", oidc_issuer: provider.issuer });

        for (const name of ["plain", "linked"]) {
            assert.strictEqual((await login(name, "correct horse")).username, name);
            assert.strictEqual(await login(name, "wrong"), null);
        }

        await configure({ enabled: false });
        assert.strictEqual((await login("linked", "correct horse")).username, "linked");
    });

    test("an OIDC identity alone does not authenticate through the password login", async () => {
        await addUser("alice", { oidc_sub: "user-1", oidc_issuer: provider.issuer });
        assert.strictEqual(await login("alice", ""), null);
        assert.strictEqual(await login("alice", "user-1"), null);
        assert.strictEqual(await login("user-1", "user-1"), null);
    });
});
