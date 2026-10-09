// OIDC: settings schema and validation. The client secret is stored as plain text like other Kuma secrets.
const { Settings } = require("./settings");
const { log } = require("../src/util");

// Settings with this type are never returned by the "general" getSettings socket event.
const SETTINGS_TYPE = "oidc";

const DEFAULT_SCOPES = ["openid", "profile", "email"];

/**
 * Parse a comma separated scope string. "openid" is always included.
 * @param {string|string[]} value Scope list
 * @returns {string[]} Unique scopes
 */
function parseScopes(value) {
    const list = Array.isArray(value) ? value : String(value ?? "").split(/[,\s]+/);
    const scopes = list.map((s) => s.trim()).filter(Boolean);
    return [...new Set(["openid", ...(scopes.length ? scopes : DEFAULT_SCOPES)])];
}

/**
 * Build a config object from raw `oidc_*` setting values.
 * @param {object} raw Values keyed by setting name
 * @returns {object} Config with defaults applied
 */
function fromRaw(raw) {
    return {
        enabled: raw.oidc_enabled === true,
        clientId: String(raw.oidc_client_id ?? "").trim(),
        clientSecret: String(raw.oidc_client_secret ?? ""),
        issuer: String(raw.oidc_issuer ?? "").trim(),
        redirectUri: String(raw.oidc_redirect_uri ?? "").trim(),
        scopes: parseScopes(raw.oidc_scopes),
        autoRegister: raw.oidc_auto_register === true,
        autoLink: raw.oidc_auto_link === true,
        requireEmailVerified: raw.oidc_require_email_verified === true,
    };
}

/**
 * Check that a string is an absolute http(s) URL.
 * @param {string} value URL string
 * @returns {?URL} Parsed URL or null
 */
function parseHttpUrl(value) {
    try {
        const url = new URL(value);
        return url.protocol === "https:" || url.protocol === "http:" ? url : null;
    } catch (e) {
        return null;
    }
}

/**
 * Validate a config. A config with errors must not be used to enable OIDC.
 * @param {object} config Config
 * @returns {string[]} Error messages (empty when valid)
 */
function validate(config) {
    const errors = [];

    if (!config.clientId) {
        errors.push("Client ID is required");
    }
    if (!config.clientSecret) {
        errors.push("Client secret is required");
    }

    const issuer = parseHttpUrl(config.issuer);
    if (!issuer) {
        errors.push("Issuer must be an http(s) URL");
    } else if (issuer.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(issuer.hostname)) {
        errors.push("Issuer must use https");
    }

    if (!parseHttpUrl(config.redirectUri)) {
        errors.push("Redirect URI must be an http(s) URL");
    }

    return errors;
}

/**
 * Config safe to log or send to the frontend (no secret).
 * @param {object} config Config
 * @returns {object} Config with `clientSecret` replaced by `hasClientSecret`
 */
function sanitize(config) {
    const { clientSecret, ...rest } = config;
    return { ...rest, hasClientSecret: !!clientSecret };
}

/**
 * Read the stored settings keys for the OIDC type.
 * @returns {Promise<object>} Raw `oidc_*` values
 */
async function readRaw() {
    return await Settings.getSettings(SETTINGS_TYPE);
}

/**
 * Load the config from the settings table.
 * OIDC counts as enabled only if `oidc_enabled` is set and the config is valid.
 * @returns {Promise<{config: object, errors: string[]}>} Config plus validation errors
 */
async function load() {
    const config = fromRaw(await readRaw());
    const errors = validate(config);

    if (config.enabled && errors.length > 0) {
        log.warn("oidc", `OIDC is enabled but the configuration is invalid: ${errors.join("; ")}`);
        config.enabled = false;
    }

    log.debug("oidc", "Loaded config: " + JSON.stringify(sanitize(config)));
    return { config, errors };
}

/**
 * Validate and save the config. An empty or missing `clientSecret` keeps the stored secret.
 * Saving an invalid config is only allowed while OIDC stays disabled.
 * @param {object} input Partial config using the camelCase field names of load()
 * @returns {Promise<object>} Saved config without the secret (see sanitize())
 * @throws {Error} If `enabled` is true and the config is invalid
 */
async function save(input) {
    const current = fromRaw(await readRaw());

    const merged = {
        ...current,
        ...input,
        scopes: parseScopes(input.scopes ?? current.scopes),
        clientSecret: input.clientSecret || current.clientSecret,
        enabled: input.enabled ?? current.enabled,
    };

    const errors = validate(merged);
    if (merged.enabled && errors.length > 0) {
        throw new Error("Invalid OIDC configuration: " + errors.join("; "));
    }

    await Settings.setSettings(SETTINGS_TYPE, {
        oidc_enabled: !!merged.enabled,
        oidc_client_id: String(merged.clientId ?? "").trim(),
        oidc_client_secret: merged.clientSecret ?? "",
        oidc_issuer: String(merged.issuer ?? "").trim(),
        oidc_redirect_uri: String(merged.redirectUri ?? "").trim(),
        oidc_scopes: merged.scopes.join(","),
        oidc_auto_register: !!merged.autoRegister,
        oidc_auto_link: !!merged.autoLink,
        oidc_require_email_verified: !!merged.requireEmailVerified,
    });

    log.info("oidc", "Configuration saved: " + JSON.stringify(sanitize(merged)));
    return sanitize(merged);
}

module.exports = {
    SETTINGS_TYPE,
    DEFAULT_SCOPES,
    parseScopes,
    fromRaw,
    validate,
    sanitize,
    load,
    save,
};
