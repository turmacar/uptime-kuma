// OIDC: socket events for the settings page and for linking the logged-in account.
const { R } = require("redbean-node");
const { log } = require("../../src/util");
const { checkLogin, doubleCheckPassword } = require("../util-server");
const oidcConfig = require("../oidc-config");
const { oidcHandler } = require("../oidc-handler");

const BOOLEAN_FIELDS = ["enabled", "autoLink", "requireEmailVerified"];
const STRING_FIELDS = ["clientId", "clientSecret", "issuer", "redirectUri"];

/**
 * Take only the known settings from the client payload and check their types.
 * @param {any} data Payload from the client
 * @returns {object} Settings for oidcConfig.save()
 * @throws {Error} If the payload is malformed or `enabled` is missing
 */
function pickSettings(data) {
    if (data === null || typeof data !== "object" || Array.isArray(data) || typeof data.enabled !== "boolean") {
        throw new Error("Invalid data");
    }

    const picked = {};
    for (const key of BOOLEAN_FIELDS) {
        if (data[key] !== undefined) {
            if (typeof data[key] !== "boolean") {
                throw new Error("Invalid data");
            }
            picked[key] = data[key];
        }
    }
    for (const key of STRING_FIELDS) {
        if (data[key] !== undefined) {
            if (typeof data[key] !== "string") {
                throw new Error("Invalid data");
            }
            picked[key] = data[key];
        }
    }
    if (data.scopes !== undefined) {
        if (!Array.isArray(data.scopes) || data.scopes.some((s) => typeof s !== "string")) {
            throw new Error("Invalid data");
        }
        picked.scopes = data.scopes;
    }
    return picked;
}

/**
 * Check the current password of the logged-in user.
 * @param {Socket} socket Socket.io instance
 * @param {any} currentPassword Password from the client
 * @returns {Promise<void>}
 * @throws {Error} If the user has no password or it is wrong
 */
async function requirePassword(socket, currentPassword) {
    const user = await R.findOne("user", " id = ? AND active = 1 ", [socket.userID]);
    if (!user?.password) {
        throw new Error("Set a password for this account first");
    }
    await doubleCheckPassword(socket, currentPassword);
}

/**
 * Handlers for the OIDC settings
 * @param {Socket} socket Socket.io instance
 * @returns {void}
 */
module.exports.oidcSocketHandler = (socket) => {
    // The client secret is never sent back, only `hasClientSecret`
    socket.on("getOIDCSettings", async (callback) => {
        try {
            checkLogin(socket);
            const { config, errors } = await oidcConfig.load();
            callback({ ok: true, config: oidcConfig.sanitize(config), errors });
        } catch (e) {
            callback({ ok: false, msg: e.message });
        }
    });

    // The password is needed whenever the saved settings are enabled: enabling, or editing while enabled
    socket.on("setOIDCSettings", async (data, currentPassword, callback) => {
        try {
            checkLogin(socket);
            const settings = pickSettings(data);

            if (settings.enabled) {
                await requirePassword(socket, currentPassword);
            }

            const saved = await oidcConfig.save(settings);
            oidcHandler.reset();
            log.info("oidc", `Settings saved by user id ${socket.userID}`);

            callback({ ok: true, msg: "Saved.", msgi18n: true, config: saved });
        } catch (e) {
            callback({ ok: false, msg: e.message });
        }
    });

    socket.on("testOIDCConnection", async (issuer, callback) => {
        try {
            checkLogin(socket);

            const errors = oidcConfig.validate({
                clientId: "x",
                clientSecret: "x",
                issuer: typeof issuer === "string" ? issuer.trim() : "",
                redirectUri: "http://localhost",
            });
            if (errors.length > 0) {
                throw new Error(errors.join("; "));
            }

            const result = await oidcHandler.testConnection(issuer.trim());
            callback({ ok: true, ...result });
        } catch (e) {
            callback({ ok: false, msg: e.message });
        }
    });

    socket.on("getOIDCInfo", async (callback) => {
        try {
            checkLogin(socket);
            const user = await R.findOne("user", " id = ? AND active = 1 ", [socket.userID]);
            callback({ ok: true, info: user.getOIDCInfo() });
        } catch (e) {
            callback({ ok: false, msg: e.message });
        }
    });

    socket.on("unlinkOIDC", async (currentPassword, callback) => {
        try {
            checkLogin(socket);
            await requirePassword(socket, currentPassword);

            const user = await R.findOne("user", " id = ? AND active = 1 ", [socket.userID]);
            await user.unlinkOIDC();
            log.info("oidc", `Identity unlinked from user ${user.username}`);

            callback({ ok: true, msg: "Saved.", msgi18n: true });
        } catch (e) {
            callback({ ok: false, msg: e.message });
        }
    });
};
