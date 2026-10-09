const { describe, test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const dayjs = require("dayjs");
const { OIDCHandler } = require("../../server/oidc-handler");

dayjs.extend(require("dayjs/plugin/utc"));

const MIGRATIONS = path.join(__dirname, "../../db/knex_migrations");
const ISSUER = "https://auth.example.com/application/o/kuma/";

describe("OIDC users: model, migration and resolution", () => {
    let R;
    let User;
    let tmpDir;

    /**
     * Insert a local user.
     * @param {string} username Username
     * @param {object} extra Extra column values
     * @returns {Promise<User>} Reloaded user bean
     */
    async function addUser(username, extra = {}) {
        const bean = R.dispense("user");
        bean.username = username;
        bean.password = "hash";
        Object.assign(bean, extra);
        const id = await R.store(bean);
        return await R.findOne("user", " id = ? ", [id]);
    }

    before(async () => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "kuma-oidc-"));

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
        await R.knex.migrate.latest({ directory: MIGRATIONS });
        await R.autoloadModels(path.join(__dirname, "../../server/model"));
        User = require("../../server/model/user");
    });

    after(async () => {
        await R.knex.destroy();
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    beforeEach(async () => {
        await R.exec("DELETE FROM `user`");
    });

    test("new columns exist and default to NULL", async () => {
        const user = await addUser("alice");
        assert.strictEqual(user.oidc_sub, null);
        assert.strictEqual(user.oidc_issuer, null);
        assert.strictEqual(user.last_oidc_login, null);
        assert.deepStrictEqual(user.getOIDCInfo(), { linked: false, sub: null, issuer: null, lastLogin: null });
    });

    test("an identity can belong to only one user, unlinked users are unrestricted", async () => {
        await addUser("a");
        await addUser("b");
        await addUser("c", { oidc_sub: "s1", oidc_issuer: ISSUER });
        await addUser("d", { oidc_sub: "s1", oidc_issuer: "https://other.example.com" });
        await assert.rejects(addUser("e", { oidc_sub: "s1", oidc_issuer: ISSUER }));
    });

    test("findByOIDC finds the linked active user", async () => {
        const alice = await addUser("alice", { oidc_sub: "s1", oidc_issuer: ISSUER });
        const found = await User.findByOIDC("s1", ISSUER);
        assert.strictEqual(found.id, alice.id);
        assert.ok(found instanceof User);
    });

    test("findByOIDC does not match another subject, issuer, or an inactive user", async () => {
        await addUser("alice", { oidc_sub: "s1", oidc_issuer: ISSUER });
        await addUser("bob", { oidc_sub: "s2", oidc_issuer: ISSUER, active: false });

        assert.strictEqual(await User.findByOIDC("other", ISSUER), null);
        assert.strictEqual(await User.findByOIDC("s1", "https://other.example.com"), null);
        assert.strictEqual(await User.findByOIDC("s2", ISSUER), null);
        assert.strictEqual(await User.findByOIDC("S1", ISSUER), null);
    });

    test("findByOIDC ignores empty arguments", async () => {
        await addUser("alice");
        assert.strictEqual(await User.findByOIDC(null, null), null);
        assert.strictEqual(await User.findByOIDC("", ISSUER), null);
        assert.strictEqual(await User.findByOIDC("s1", ""), null);
    });

    test("linkOIDC stores the identity and login time", async () => {
        const alice = await addUser("alice");
        await alice.linkOIDC("s1", ISSUER);

        const stored = await R.findOne("user", " id = ? ", [alice.id]);
        assert.strictEqual(stored.oidc_sub, "s1");
        assert.strictEqual(stored.oidc_issuer, ISSUER);
        assert.ok(stored.last_oidc_login);
        assert.strictEqual(stored.getOIDCInfo().linked, true);
        assert.strictEqual((await User.findByOIDC("s1", ISSUER)).id, alice.id);
    });

    test("linkOIDC is idempotent for the same identity", async () => {
        const alice = await addUser("alice");
        await alice.linkOIDC("s1", ISSUER);
        await alice.linkOIDC("s1", ISSUER);
        assert.strictEqual(alice.oidc_sub, "s1");
    });

    test("linkOIDC refuses to replace an existing link", async () => {
        const alice = await addUser("alice", { oidc_sub: "s1", oidc_issuer: ISSUER });
        await assert.rejects(alice.linkOIDC("s2", ISSUER), /already linked/);
        await assert.rejects(alice.linkOIDC("s1", "https://other.example.com"), /already linked/);

        const stored = await R.findOne("user", " id = ? ", [alice.id]);
        assert.strictEqual(stored.oidc_sub, "s1");
    });

    test("linkOIDC refuses an identity that belongs to another user", async () => {
        await addUser("alice", { oidc_sub: "s1", oidc_issuer: ISSUER });
        const bob = await addUser("bob");
        await assert.rejects(bob.linkOIDC("s1", ISSUER));

        const stored = await R.findOne("user", " id = ? ", [bob.id]);
        assert.strictEqual(stored.oidc_sub, null);
    });

    test("linkOIDC requires subject and issuer", async () => {
        const alice = await addUser("alice");
        await assert.rejects(alice.linkOIDC("", ISSUER), /required/);
        await assert.rejects(alice.linkOIDC("s1", null), /required/);
    });

    test("recordOIDCLogin updates the login time", async () => {
        const alice = await addUser("alice", { oidc_sub: "s1", oidc_issuer: ISSUER });
        await alice.recordOIDCLogin();

        const stored = await R.findOne("user", " id = ? ", [alice.id]);
        assert.ok(stored.last_oidc_login);
        assert.strictEqual(stored.oidc_sub, "s1");
    });

    describe("resolveUser", () => {
        const handler = new OIDCHandler();
        const identity = (extra = {}) => ({ sub: "s1", issuer: ISSUER, preferredUsername: "alice", ...extra });

        test("returns the user already linked to the identity", async () => {
            const alice = await addUser("alice", { oidc_sub: "s1", oidc_issuer: ISSUER });
            const user = await handler.resolveUser({ autoLink: false }, identity({ preferredUsername: "other" }));
            assert.strictEqual(user.id, alice.id);
        });

        test("without autoLink an unlinked identity is rejected even if the username matches", async () => {
            await addUser("alice");
            await assert.rejects(handler.resolveUser({ autoLink: false }, identity()), (e) => e.code === "no_account");
        });

        test("autoLink links the user whose username matches and keeps the link", async () => {
            const alice = await addUser("alice");
            const user = await handler.resolveUser({ autoLink: true }, identity());
            assert.strictEqual(user.id, alice.id);

            const stored = await R.findOne("user", " id = ? ", [alice.id]);
            assert.strictEqual(stored.oidc_sub, "s1");
            assert.strictEqual(stored.oidc_issuer, ISSUER);

            // Next login no longer needs autoLink
            assert.strictEqual((await handler.resolveUser({ autoLink: false }, identity())).id, alice.id);
        });

        test("autoLink does not match a different username or a different case", async () => {
            await addUser("alice");
            for (const preferredUsername of ["bob", "Alice", "", null]) {
                await assert.rejects(
                    handler.resolveUser({ autoLink: true }, identity({ preferredUsername })),
                    (e) => e.code === "no_account"
                );
            }
        });

        test("autoLink never takes over an account linked to another identity", async () => {
            const alice = await addUser("alice", { oidc_sub: "s-original", oidc_issuer: ISSUER });
            await assert.rejects(
                handler.resolveUser({ autoLink: true }, identity({ sub: "s-attacker" })),
                (e) => e.code === "already_linked"
            );

            const stored = await R.findOne("user", " id = ? ", [alice.id]);
            assert.strictEqual(stored.oidc_sub, "s-original");
        });

        test("autoLink refuses an account without a password", async () => {
            const alice = await addUser("alice", { password: null });
            await assert.rejects(
                handler.resolveUser({ autoLink: true }, identity()),
                (e) => e.code === "password_required"
            );

            const stored = await R.findOne("user", " id = ? ", [alice.id]);
            assert.strictEqual(stored.oidc_sub, null);
        });

        test("autoLink ignores inactive users", async () => {
            await addUser("alice", { active: false });
            await assert.rejects(handler.resolveUser({ autoLink: true }, identity()), (e) => e.code === "no_account");
        });

        test("an unknown identity never creates an account", async () => {
            await assert.rejects(
                handler.resolveUser({ autoLink: true }, identity({ preferredUsername: "newcomer" })),
                (e) => e.code === "no_account"
            );
            assert.strictEqual((await R.getAll("SELECT id FROM `user`")).length, 0);
        });
    });

    test("migration rolls back cleanly and can be re-applied", async () => {
        await addUser("alice", { oidc_sub: "s1", oidc_issuer: ISSUER });

        await R.knex.migrate.down({ directory: MIGRATIONS });
        const columns = Object.keys(await R.knex("user").columnInfo());
        assert.ok(!columns.some((c) => c.startsWith("oidc_") || c === "last_oidc_login"));
        assert.strictEqual((await R.getAll("SELECT username FROM `user`"))[0].username, "alice");

        await R.knex.migrate.latest({ directory: MIGRATIONS });
        const again = Object.keys(await R.knex("user").columnInfo());
        assert.ok(again.includes("oidc_sub") && again.includes("oidc_issuer") && again.includes("last_oidc_login"));
    });
});
