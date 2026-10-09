const { BeanModel } = require("redbean-node/dist/bean-model");
const passwordHash = require("../password-hash");
const { R } = require("redbean-node");
const jwt = require("jsonwebtoken");
const dayjs = require("dayjs");
const { shake256, SHAKE256_LENGTH } = require("../util-server");

class User extends BeanModel {
    /**
     * Reset user password
     * Fix #1510, as in the context reset-password.js, there is no auto model mapping. Call this static function instead.
     * @param {number} userID ID of user to update
     * @param {string} newPassword Users new password
     * @returns {Promise<void>}
     */
    static async resetPassword(userID, newPassword) {
        await R.exec("UPDATE `user` SET password = ? WHERE id = ? ", [
            await passwordHash.generate(newPassword),
            userID,
        ]);
    }

    /**
     * Reset this users password
     * @param {string} newPassword Users new password
     * @returns {Promise<void>}
     */
    async resetPassword(newPassword) {
        const hashedPassword = await passwordHash.generate(newPassword);

        await R.exec("UPDATE `user` SET password = ? WHERE id = ? ", [hashedPassword, this.id]);

        this.password = hashedPassword;
    }

    /**
     * OIDC: find the active user linked to an external identity
     * @param {string} sub Subject claim of the ID token
     * @param {string} issuer Issuer claim of the ID token
     * @returns {Promise<?User>} The linked user, or null
     */
    static async findByOIDC(sub, issuer) {
        if (!sub || !issuer) {
            return null;
        }
        const user = await R.findOne("user", " oidc_sub = ? AND oidc_issuer = ? AND active = 1 ", [sub, issuer]);
        // Case-insensitive collations (MariaDB) can match values that differ in case
        return user && user.oidc_sub === sub && user.oidc_issuer === issuer ? user : null;
    }

    /**
     * OIDC: link this user to an external identity and record the login
     * @param {string} sub Subject claim of the ID token
     * @param {string} issuer Issuer claim of the ID token
     * @returns {Promise<void>}
     * @throws {Error} If the user is already linked to a different identity, or the identity belongs to another user
     */
    async linkOIDC(sub, issuer) {
        if (!sub || !issuer) {
            throw new Error("OIDC subject and issuer are required");
        }
        if (this.oidc_sub && (this.oidc_sub !== sub || this.oidc_issuer !== issuer)) {
            throw new Error("User is already linked to a different OIDC identity");
        }

        await R.exec("UPDATE `user` SET oidc_sub = ?, oidc_issuer = ?, last_oidc_login = ? WHERE id = ? ", [
            sub,
            issuer,
            R.isoDateTimeMillis(dayjs.utc()),
            this.id,
        ]);

        this.oidc_sub = sub;
        this.oidc_issuer = issuer;
    }

    /**
     * OIDC: record a successful OIDC login for this user
     * @returns {Promise<void>}
     */
    async recordOIDCLogin() {
        const now = R.isoDateTimeMillis(dayjs.utc());
        await R.exec("UPDATE `user` SET last_oidc_login = ? WHERE id = ? ", [now, this.id]);
        this.last_oidc_login = now;
    }

    /**
     * OIDC: metadata about the linked identity
     * @returns {{linked: boolean, sub: ?string, issuer: ?string, lastLogin: ?string}} Link status
     */
    getOIDCInfo() {
        return {
            linked: !!this.oidc_sub,
            sub: this.oidc_sub ?? null,
            issuer: this.oidc_issuer ?? null,
            lastLogin: this.last_oidc_login ?? null,
        };
    }

    /**
     * Create a new JWT for a user
     * @param {User} user The User to create a JsonWebToken for
     * @param {string} jwtSecret The key used to sign the JsonWebToken
     * @returns {string} the JsonWebToken as a string
     */
    static createJWT(user, jwtSecret) {
        return jwt.sign(
            {
                username: user.username,
                h: shake256(user.password, SHAKE256_LENGTH),
            },
            jwtSecret
        );
    }
}

module.exports = User;
