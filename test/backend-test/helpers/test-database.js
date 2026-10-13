const fs = require("fs");
const os = require("os");
const path = require("path");

/**
 * Create a SQLite database with all tables and migrations, wired into redbean-node.
 * Test files run in separate processes, so the global `R` is private to each file.
 * @returns {Promise<{R: object, cleanup: Function}>} Redbean instance and a cleanup function
 */
async function setupTestDatabase() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kuma-test-"));

    const Dialect = require("knex/lib/dialects/sqlite3/index.js");
    Dialect.prototype._driver = () => require("@louislam/sqlite3");
    const db = require("knex")({
        client: Dialect,
        connection: { filename: path.join(dir, "test.db") },
        useNullAsDefault: true,
    });

    const { R } = require("redbean-node");
    R.setup(db);
    await require("../../../db/knex_init_db.js").createTables();
    await R.knex.migrate.latest({ directory: path.join(__dirname, "../../../db/knex_migrations") });
    await R.autoloadModels(path.join(__dirname, "../../../server/model"));

    return {
        R,
        cleanup: async () => {
            await R.knex.destroy();
            fs.rmSync(dir, { recursive: true, force: true });
        },
    };
}

module.exports = { setupTestDatabase };
