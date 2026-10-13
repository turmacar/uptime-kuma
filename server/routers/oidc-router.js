// OIDC: HTTP endpoints for the browser redirect flow. The result is handed to the socket.io login via a one-time ticket.
const crypto = require("crypto");
const express = require("express");
const { R } = require("redbean-node");
const { log } = require("../../src/util");
const { allowDevAllOrigin } = require("../util-server");
const oidcConfig = require("../oidc-config");
const { oidcHandler, OIDCError } = require("../oidc-handler");
const { ExpiringStore, oidcTickets } = require("../oidc-store");
const { oidcRateLimiter } = require("../rate-limiter");

const COOKIE_NAME = "uptime-kuma-oidc";
const COOKIE_PATH = "/auth/oidc";
const PENDING_TTL_MS = 10 * 60 * 1000;

// The frontend route that receives `#ticket=...` or `#error=<code>`.
const RESULT_PATH = "/oidc-callback";

/**
 * Read one cookie from a Cookie header.
 * @param {?string} header Cookie header value
 * @param {string} name Cookie name
 * @returns {?string} Cookie value
 */
function readCookie(header, name) {
    for (const part of (header ?? "").split(";")) {
        const index = part.indexOf("=");
        if (index > 0 && part.slice(0, index).trim() === name) {
            return part.slice(index + 1).trim();
        }
    }
    return null;
}

/**
 * Constant-time string comparison.
 * @param {string} a First value
 * @param {string} b Second value
 * @returns {boolean} True if equal
 */
function safeEqual(a, b) {
    const digest = (v) => crypto.createHash("sha256").update(v).digest();
    return crypto.timingSafeEqual(digest(a), digest(b));
}

/**
 * Keep only plain string query parameters (Express may parse arrays and objects).
 * @param {object} query Parsed query
 * @returns {object} String-only copy
 */
function stringParams(query) {
    return Object.fromEntries(Object.entries(query).filter(([, v]) => typeof v === "string"));
}

/**
 * Make provider-controlled text safe for one log line (no line breaks, bounded length).
 * @param {any} text Text to clean
 * @returns {string} Single-line text
 */
function forLog(text) {
    return String(text ?? "")
        .replace(/[\u0000-\u001f\u007f]+/g, " ")
        .slice(0, 300);
}

/**
 * Client IP, honouring the trusted proxy setting like the socket logins do.
 * @param {express.Request} req Request
 * @returns {Promise<string>} IP address
 */
async function defaultClientIP(req) {
    const { UptimeKumaServer } = require("../uptime-kuma-server");
    return await UptimeKumaServer.getInstance().getClientIPwithProxy(req.socket.remoteAddress, req.headers);
}

/**
 * Create the OIDC router. Dependencies can be replaced in tests.
 * @param {object} options Overrides
 * @param {object} options.handler OIDC handler
 * @param {Function} options.loadConfig Returns `{config}` like oidc-config load()
 * @param {object} options.tickets Store receiving the one-time tickets
 * @param {object} options.limiter Rate limiter with a `pass()` method
 * @param {Function} options.getClientIP Resolves the client IP of a request for the log
 * @returns {express.Router} Router handling /auth/oidc/*
 */
function createOIDCRouter({
    handler = oidcHandler,
    loadConfig = () => oidcConfig.load(),
    tickets = oidcTickets,
    limiter = oidcRateLimiter,
    getClientIP = defaultClientIP,
} = {}) {
    const router = express.Router();
    // Pending logins keyed by `state`; the cookie binds each one to the browser that started it.
    const pending = new ExpiringStore({ ttlMs: PENDING_TTL_MS, maxEntries: 500 });

    /**
     * Redirect to the frontend with only a fixed code or a ticket in the fragment.
     * @param {express.Response} res Response
     * @param {object} params Fragment parameters
     * @returns {void}
     */
    const finish = (res, params) => {
        res.redirect(`${RESULT_PATH}#${new URLSearchParams(params).toString()}`);
    };

    router.get("/auth/oidc/status", async (req, res) => {
        allowDevAllOrigin(res);
        res.set("Cache-Control", "no-store");
        try {
            const { config } = await loadConfig();
            // The email verification link is only a pointer to the provider, shown after a refused sign-in
            res.json({
                enabled: config.enabled,
                ...(config.enabled && config.verifyEmailUrl ? { verifyEmailUrl: config.verifyEmailUrl } : {}),
            });
        } catch (e) {
            log.error("oidc", "Could not load the configuration: " + e.message);
            res.json({ enabled: false });
        }
    });

    router.use("/auth/oidc", async (req, res, next) => {
        res.set("Cache-Control", "no-store");

        if (!(await limiter.pass())) {
            return res.status(429).send("Too many requests");
        }

        try {
            const { config } = await loadConfig();
            if (!config.enabled) {
                return res.sendStatus(404);
            }
            req.oidcConfig = config;
            next();
        } catch (e) {
            log.error("oidc", "Could not load the configuration: " + e.message);
            res.sendStatus(500);
        }
    });

    router.get("/auth/oidc/login", async (req, res) => {
        const config = req.oidcConfig;
        const ip = await getClientIP(req);
        try {
            const { url, checks } = await handler.createAuthorization(config);
            const binding = crypto.randomBytes(32).toString("base64url");
            pending.put(checks.state, { checks, binding });

            res.cookie(COOKIE_NAME, binding, {
                httpOnly: true,
                sameSite: "lax", // the callback is a cross-site top-level GET
                secure: new URL(config.redirectUri).protocol === "https:",
                path: COOKIE_PATH,
                maxAge: PENDING_TTL_MS,
            });
            log.info("oidc", `Login started. IP=${ip}`);
            res.redirect(url);
        } catch (e) {
            log.warn("oidc", `Could not start the login: ${forLog(e.detail ?? e.message)}. IP=${ip}`);
            finish(res, { error: e instanceof OIDCError ? e.code : "server_error" });
        }
    });

    router.get("/auth/oidc/callback", async (req, res) => {
        const config = req.oidcConfig;
        const ip = await getClientIP(req);
        res.clearCookie(COOKIE_NAME, { path: COOKIE_PATH });

        try {
            // Taking the entry invalidates the state even if the rest fails
            const entry = pending.take(req.query.state);
            const binding = readCookie(req.headers.cookie, COOKIE_NAME);
            if (!entry || !binding || !safeEqual(binding, entry.binding)) {
                throw new OIDCError("no_session", "Login session expired, please try again");
            }

            const identity = await handler.handleCallback(config, stringParams(req.query), entry.checks);
            const user = await handler.resolveUser(config, identity);

            const ticket = tickets.putRandom({ userID: user.id });
            log.info("oidc", `Identity verified for user ${forLog(user.username)}. IP=${ip}`);
            finish(res, { ticket });
        } catch (e) {
            if (e instanceof OIDCError) {
                log.warn("oidc", `Login failed (${e.code}): ${forLog(e.detail ?? e.message)}. IP=${ip}`);
                finish(res, { error: e.code });
            } else {
                log.error("oidc", `Login failed: ${forLog(e.message)}. IP=${ip}`);
                finish(res, { error: "server_error" });
            }
        }
    });

    return router;
}

/**
 * Exchange a one-time ticket from the callback for the user it was issued to.
 * @param {any} ticket Ticket from the browser
 * @param {object} options Overrides
 * @param {object} options.tickets Store the ticket was issued into
 * @param {Function} options.loadConfig Returns `{config}` like oidc-config load()
 * @param {Function} options.findUser Loads the active user by id
 * @returns {Promise<?object>} The active user, or null if the ticket is invalid, expired or OIDC is disabled
 */
async function redeemOIDCTicket(
    ticket,
    {
        tickets = oidcTickets,
        loadConfig = () => oidcConfig.load(),
        findUser = (id) => R.findOne("user", " id = ? AND active = 1 ", [id]),
    } = {}
) {
    const entry = tickets.take(ticket);
    if (!entry) {
        return null;
    }
    const { config } = await loadConfig();
    if (!config.enabled) {
        return null;
    }
    return (await findUser(entry.userID)) ?? null;
}

module.exports = { createOIDCRouter, redeemOIDCTicket };
