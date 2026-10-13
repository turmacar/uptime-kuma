const { describe, test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert");
const express = require("express");
const { log } = require("../../src/util");
const { OIDCHandler, OIDCError } = require("../../server/oidc-handler");
const { ExpiringStore } = require("../../server/oidc-store");
const { createOIDCRouter, redeemOIDCTicket } = require("../../server/routers/oidc-router");
const { FakeProvider } = require("./helpers/fake-oidc-provider");

describe("OIDC router", () => {
    const provider = new FakeProvider();
    let app;
    let base;
    let config;
    const handler = new OIDCHandler();
    const tickets = new ExpiringStore({ ttlMs: 60000, maxEntries: 10 });
    let allow;
    let logged;

    before(async () => {
        await provider.start();
        app = express();
        app.use(
            createOIDCRouter({
                handler,
                loadConfig: async () => ({ config, errors: [] }),
                tickets,
                limiter: { pass: async () => allow },
                getClientIP: async () => "203.0.113.7",
            })
        );
        await new Promise((resolve) => {
            app.server = app.listen(0, "127.0.0.1", resolve);
        });
        base = `http://127.0.0.1:${app.server.address().port}`;

        // Capture every log line instead of printing it
        for (const level of ["debug", "info", "warn", "error"]) {
            log[level] = (...args) => logged.push(args.map(String).join(" "));
        }
    });

    after(() => {
        for (const level of ["debug", "info", "warn", "error"]) {
            delete log[level];
        }
        provider.stop();
        app.server.close();
    });

    beforeEach(() => {
        logged = [];
        allow = true;
        provider.claims = {};
        provider.tokenRequests = 0;
        tickets.entries.clear();
        handler.reset();
        handler.resolveUser = async (cfg, identity) => {
            if (identity.sub !== "user-1") {
                throw new OIDCError("no_account", "No account is linked to this identity");
            }
            return { id: 7, username: "me" };
        };
        config = {
            enabled: true,
            clientId: "kuma",
            clientSecret: "secret",
            issuer: provider.issuer,
            redirectUri: "https://uptime.example.com/auth/oidc/callback",
            scopes: ["openid", "profile", "email"],
            requireEmailVerified: false,
        };
    });

    /**
     * GET without following redirects.
     * @param {string} path Path and query
     * @param {?string} cookie Cookie header value
     * @returns {Promise<Response>} Response
     */
    function get(path, cookie = null) {
        return fetch(base + path, { redirect: "manual", headers: cookie ? { cookie } : {} });
    }

    /**
     * Start a login and tell the fake provider what it must see at the token endpoint.
     * @returns {Promise<{state: string, cookie: string, setCookie: string}>} Values for the callback
     */
    async function startLogin() {
        const res = await get("/auth/oidc/login");
        assert.strictEqual(res.status, 302);
        const url = new URL(res.headers.get("location"));
        provider.expected = {
            nonce: url.searchParams.get("nonce"),
            challenge: url.searchParams.get("code_challenge"),
        };
        const setCookie = res.headers.getSetCookie()[0];
        return { state: url.searchParams.get("state"), cookie: setCookie.split(";")[0], setCookie };
    }

    /**
     * Fragment parameters of a redirect to the frontend.
     * @param {Response} res Response
     * @returns {URLSearchParams} Fragment parameters
     */
    function fragment(res) {
        assert.strictEqual(res.status, 302);
        const location = res.headers.get("location");
        assert.ok(location.startsWith("/oidc-callback#"), location);
        return new URLSearchParams(location.split("#")[1]);
    }

    test("status tells the login page whether OIDC is enabled and nothing else", async () => {
        const on = await get("/auth/oidc/status");
        assert.strictEqual(on.status, 200);
        assert.strictEqual(on.headers.get("cache-control"), "no-store");
        assert.deepStrictEqual(await on.json(), { enabled: true });

        config.enabled = false;
        assert.deepStrictEqual(await (await get("/auth/oidc/status")).json(), { enabled: false });
    });

    test("status only exposes the email verification link while OIDC is enabled", async () => {
        config.verifyEmailUrl = "https://auth.example.com/if/user/";
        assert.deepStrictEqual(await (await get("/auth/oidc/status")).json(), {
            enabled: true,
            verifyEmailUrl: "https://auth.example.com/if/user/",
        });

        config.verifyEmailUrl = "";
        assert.deepStrictEqual(await (await get("/auth/oidc/status")).json(), { enabled: true });

        config.verifyEmailUrl = "https://auth.example.com/if/user/";
        config.enabled = false;
        assert.deepStrictEqual(await (await get("/auth/oidc/status")).json(), { enabled: false });
    });

    test("status is not blocked by the OIDC rate limit", async () => {
        allow = false;
        assert.strictEqual((await get("/auth/oidc/status")).status, 200);
    });

    test("is a 404 while OIDC is disabled", async () => {
        config.enabled = false;
        assert.strictEqual((await get("/auth/oidc/login")).status, 404);
        assert.strictEqual((await get("/auth/oidc/callback?code=x&state=y")).status, 404);
    });

    test("is rate limited", async () => {
        allow = false;
        assert.strictEqual((await get("/auth/oidc/login")).status, 429);
        assert.strictEqual(provider.tokenRequests, 0);
    });

    test("login redirects to the provider and sets a locked-down cookie", async () => {
        const res = await get("/auth/oidc/login");
        assert.strictEqual(res.status, 302);
        assert.strictEqual(res.headers.get("cache-control"), "no-store");

        const url = new URL(res.headers.get("location"));
        assert.strictEqual(url.origin + url.pathname, `${provider.issuer}/authorize`);
        assert.ok(url.searchParams.get("state"));

        const cookie = res.headers.getSetCookie()[0];
        assert.match(cookie, /^uptime-kuma-oidc=/);
        assert.match(cookie, /HttpOnly/);
        assert.match(cookie, /SameSite=Lax/);
        assert.match(cookie, /Secure/);
        assert.match(cookie, /Path=\/auth\/oidc/);
        assert.match(cookie, /Max-Age=600/);
        assert.ok(!cookie.includes(url.searchParams.get("state")));
    });

    test("cookie is not Secure when the redirect URI is plain http", async () => {
        config.redirectUri = "http://localhost:3001/auth/oidc/callback";
        const res = await get("/auth/oidc/login");
        assert.doesNotMatch(res.headers.getSetCookie()[0], /Secure/);
    });

    test("login reports an unreachable provider without leaking details", async () => {
        config.issuer = "http://127.0.0.1:1";
        const res = await get("/auth/oidc/login");
        assert.strictEqual(fragment(res).get("error"), "discovery_failed");
        assert.strictEqual(res.headers.getSetCookie().length, 0);
    });

    test("full flow ends in a ticket for the linked user", async () => {
        const { state, cookie } = await startLogin();
        const res = await get(`/auth/oidc/callback?code=good-code&state=${state}`, cookie);

        const ticket = fragment(res).get("ticket");
        assert.ok(ticket);
        assert.strictEqual(fragment(res).get("error"), null);

        const user = await redeemOIDCTicket(ticket, {
            tickets,
            loadConfig: async () => ({ config }),
            findUser: async (id) => ({ id, username: "me" }),
        });
        assert.strictEqual(user.id, 7);
    });

    test("callback without the cookie is rejected before the token endpoint", async () => {
        const { state } = await startLogin();
        const res = await get(`/auth/oidc/callback?code=good-code&state=${state}`);
        assert.strictEqual(fragment(res).get("error"), "no_session");
        assert.strictEqual(provider.tokenRequests, 0);
    });

    test("a cookie from another login does not match (login CSRF)", async () => {
        const victim = await startLogin();
        const attacker = await startLogin();
        const res = await get(`/auth/oidc/callback?code=good-code&state=${attacker.state}`, victim.cookie);
        assert.strictEqual(fragment(res).get("error"), "no_session");
        assert.strictEqual(provider.tokenRequests, 0);

        // The attacker's state is spent
        const retry = await get(`/auth/oidc/callback?code=good-code&state=${attacker.state}`, attacker.cookie);
        assert.strictEqual(fragment(retry).get("error"), "no_session");
    });

    test("an unknown, missing or repeated state is rejected", async () => {
        const { state, cookie } = await startLogin();
        for (const query of ["state=unknown", "", "state=a&state=b", "state[x]=1"]) {
            const res = await get(`/auth/oidc/callback?code=good-code&${query}`, cookie);
            assert.strictEqual(fragment(res).get("error"), "no_session", query);
        }

        // Real state still works: failures above must not have consumed it
        const ok = await get(`/auth/oidc/callback?code=good-code&state=${state}`, cookie);
        assert.ok(fragment(ok).get("ticket"));
    });

    test("a callback cannot be replayed", async () => {
        const { state, cookie } = await startLogin();
        const url = `/auth/oidc/callback?code=good-code&state=${state}`;
        assert.ok(fragment(await get(url, cookie)).get("ticket"));
        assert.strictEqual(fragment(await get(url, cookie)).get("error"), "no_session");
    });

    test("a provider error becomes a fixed code, never reflected text", async () => {
        const { state, cookie } = await startLogin();
        const res = await get(
            `/auth/oidc/callback?error=access_denied&error_description=${encodeURIComponent("<script>alert(1)</script>")}&state=${state}`,
            cookie
        );
        assert.strictEqual(fragment(res).get("error"), "provider_error");
        assert.ok(!res.headers.get("location").includes("script"));
        assert.strictEqual(provider.tokenRequests, 0);
    });

    test("an identity without a linked account gets no ticket", async () => {
        const { state, cookie } = await startLogin();
        provider.claims = { sub: "stranger" };
        const res = await get(`/auth/oidc/callback?code=good-code&state=${state}`, cookie);
        assert.strictEqual(fragment(res).get("error"), "no_account");
        assert.strictEqual(tickets.entries.size, 0);
    });

    test("an invalid ID token gets no ticket", async () => {
        const { state, cookie } = await startLogin();
        provider.claims = { nonce: "attacker-nonce" };
        const res = await get(`/auth/oidc/callback?code=good-code&state=${state}`, cookie);
        assert.strictEqual(fragment(res).get("error"), "invalid_callback");
        assert.strictEqual(tickets.entries.size, 0);
    });

    test("email_verified is enforced when configured", async () => {
        config.requireEmailVerified = true;
        const { state, cookie } = await startLogin();
        provider.claims = { email_verified: false };
        const res = await get(`/auth/oidc/callback?code=good-code&state=${state}`, cookie);
        assert.strictEqual(fragment(res).get("error"), "email_not_verified");
        assert.strictEqual(tickets.entries.size, 0);
    });

    test("audit log lines carry the client IP and the failure code", async () => {
        const { state, cookie } = await startLogin();
        await get(`/auth/oidc/callback?code=good-code&state=${state}`, cookie);
        await get("/auth/oidc/callback?code=good-code&state=unknown", cookie);

        const has = (...parts) => logged.some((line) => parts.every((p) => line.includes(p)));
        assert.ok(has("Login started", "IP=203.0.113.7"), logged.join("\n"));
        assert.ok(has("Identity verified for user me", "IP=203.0.113.7"), logged.join("\n"));
        assert.ok(has("Login failed (no_session)", "IP=203.0.113.7"), logged.join("\n"));
    });

    test("logs never contain the state, code, ticket, cookie value or client secret", async () => {
        config.clientSecret = "s3cr3t-client-value";
        const { state, cookie } = await startLogin();
        const res = await get(`/auth/oidc/callback?code=good-code&state=${state}`, cookie);
        const ticket = fragment(res).get("ticket");
        assert.ok(ticket);

        const output = logged.join("\n");
        const secrets = [
            state,
            "good-code",
            ticket,
            cookie.split("=")[1],
            config.clientSecret,
            provider.expected.nonce,
            provider.expected.challenge,
        ];
        for (const secret of secrets) {
            assert.ok(!output.includes(secret), `log contains ${secret}`);
        }
    });

    test("provider error text cannot forge or flood log lines", async () => {
        const { state, cookie } = await startLogin();
        const description = "x\n2026-01-01 [AUTH] INFO: Successfully logged in user admin\r" + "A".repeat(5000);
        await get(
            `/auth/oidc/callback?error=access_denied&error_description=${encodeURIComponent(description)}&state=${state}`,
            cookie
        );

        const line = logged.find((l) => l.includes("provider_error"));
        assert.ok(line);
        assert.ok(!/[\r\n]/.test(line));
        assert.ok(line.length < 500, `line is ${line.length} characters`);
    });

    test("an unexpected error is reported as server_error", async () => {
        handler.resolveUser = async () => {
            throw new Error("db exploded: secret details");
        };
        const { state, cookie } = await startLogin();
        const res = await get(`/auth/oidc/callback?code=good-code&state=${state}`, cookie);
        assert.strictEqual(fragment(res).get("error"), "server_error");
        assert.ok(!res.headers.get("location").includes("exploded"));
    });
});

describe("OIDC ticket redemption", () => {
    const enabled = async () => ({ config: { enabled: true } });
    const findUser = async (id) => ({ id, username: "me" });
    let clock;
    let tickets;

    beforeEach(() => {
        clock = { now: 1000 };
        tickets = new ExpiringStore({ ttlMs: 60000, maxEntries: 10, now: () => clock.now });
    });

    test("returns the user once", async () => {
        const ticket = tickets.putRandom({ userID: 3 });
        const options = { tickets, loadConfig: enabled, findUser };
        assert.strictEqual((await redeemOIDCTicket(ticket, options)).id, 3);
        assert.strictEqual(await redeemOIDCTicket(ticket, options), null);
    });

    test("rejects unknown, forged and non-string tickets", async () => {
        tickets.putRandom({ userID: 3 });
        const options = { tickets, loadConfig: enabled, findUser };
        assert.strictEqual(await redeemOIDCTicket("forged", options), null);
        assert.strictEqual(await redeemOIDCTicket(undefined, options), null);
        assert.strictEqual(await redeemOIDCTicket({ userID: 3 }, options), null);
    });

    test("rejects an expired ticket", async () => {
        const ticket = tickets.putRandom({ userID: 3 });
        clock.now += 60000;
        assert.strictEqual(await redeemOIDCTicket(ticket, { tickets, loadConfig: enabled, findUser }), null);
    });

    test("rejects the ticket once OIDC has been disabled", async () => {
        const ticket = tickets.putRandom({ userID: 3 });
        const disabled = async () => ({ config: { enabled: false } });
        assert.strictEqual(await redeemOIDCTicket(ticket, { tickets, loadConfig: disabled, findUser }), null);
    });

    test("rejects the ticket if the user is gone or inactive", async () => {
        const ticket = tickets.putRandom({ userID: 3 });
        const options = { tickets, loadConfig: enabled, findUser: async () => null };
        assert.strictEqual(await redeemOIDCTicket(ticket, options), null);
    });
});
