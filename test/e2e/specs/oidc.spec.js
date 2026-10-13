import { expect, test } from "@playwright/test";
import path from "path";
import sqlite3 from "@louislam/sqlite3";
import { url } from "../../../config/playwright.config.js";
import { FakeProvider } from "../../backend-test/helpers/fake-oidc-provider";
import { login, restoreSqliteSnapshot, screenshot } from "../util-test";

const PROVIDER_PORT = 30002;
const dbFile = path.resolve(__dirname, "../../../data/playwright-test/kuma.db");

const provider = new FakeProvider();

/**
 * Run SQL against the e2e database while the server is running.
 * @param {string} sql One or more statements
 * @returns {Promise<void>}
 */
function runSql(sql) {
    return new Promise((resolve, reject) => {
        const db = new sqlite3.Database(dbFile, (openError) => {
            if (openError) {
                return reject(openError);
            }
            db.configure("busyTimeout", 5000);
            db.exec(sql, (execError) => db.close(() => (execError ? reject(execError) : resolve())));
        });
    });
}

/**
 * Point Kuma at the fake provider and link (or unlink) the admin user.
 * @param {object} options Options
 * @param {boolean} options.enabled Value of oidc_enabled
 * @param {boolean} options.linked Link the admin user to the provider's identity
 * @returns {Promise<void>}
 */
function configureOIDC({ enabled = true, linked = true } = {}) {
    const settings = {
        oidc_enabled: enabled,
        oidc_client_id: "kuma",
        oidc_client_secret: "secret",
        oidc_issuer: provider.issuer,
        oidc_redirect_uri: `${url}/auth/oidc/callback`,
    };
    const rows = Object.entries(settings)
        .map(([key, value]) => `('${key}', '${JSON.stringify(value)}', 'oidc')`)
        .join(", ");
    const identity = linked
        ? `oidc_sub = 'user-1', oidc_issuer = '${provider.issuer}'`
        : "oidc_sub = NULL, oidc_issuer = NULL";

    return runSql(`
        DELETE FROM setting WHERE type = 'oidc';
        INSERT INTO setting (key, value, type) VALUES ${rows};
        UPDATE user SET ${identity} WHERE username = 'admin';
    `);
}

/**
 * Open the dashboard and wait until the login page knows whether OIDC is enabled.
 * @param {Page} page Page
 * @returns {Promise<void>}
 */
async function openLoginPage(page) {
    const status = page.waitForResponse("**/auth/oidc/status");
    await page.goto("./dashboard");
    await status;
    await expect(page.getByRole("button", { name: "Log in" })).toBeVisible();
}

/**
 * Click the OIDC button and wait for the dashboard.
 * @param {Page} page Page
 * @returns {Promise<void>}
 */
async function loginWithOIDC(page) {
    await page.getByRole("button", { name: "Login with Authentik" }).click();
    await expect(page.getByText("Add New Monitor")).toBeVisible();
}

/**
 * @param {Page} page Page
 * @returns {Promise<void>}
 */
async function logout(page) {
    await page.getByText("A", { exact: true }).click();
    await page.getByRole("button", { name: "Log out" }).click();
    await expect(page.getByRole("button", { name: "Log in" })).toBeVisible();
}

test.describe("OIDC login", () => {
    test.beforeAll(async () => {
        await provider.start(PROVIDER_PORT);
    });

    test.afterAll(async () => {
        provider.stop();
        await restoreSqliteSnapshot();
    });

    test.beforeEach(async () => {
        await restoreSqliteSnapshot();
        provider.claims = {};
    });

    test("no OIDC button while OIDC is not configured", async ({ page }, testInfo) => {
        await openLoginPage(page);

        await expect(page.getByRole("button", { name: "Login with Authentik" })).toHaveCount(0);
        await screenshot(testInfo, page);
    });

    test("logs in through the identity provider and logs out again", async ({ page }, testInfo) => {
        await configureOIDC();
        await openLoginPage(page);
        await expect(page.getByRole("button", { name: "Login with Authentik" })).toBeVisible();
        await screenshot(testInfo, page);

        await loginWithOIDC(page);
        expect(page.url()).not.toContain("ticket");
        expect(await page.evaluate(() => !!localStorage.token)).toBe(true);
        await screenshot(testInfo, page);

        await logout(page);
        expect(await page.evaluate(() => !!localStorage.token)).toBe(false);

        // Still logged out after a reload
        await page.reload();
        await expect(page.getByRole("button", { name: "Log in" })).toBeVisible();
        await expect(page.getByRole("button", { name: "Login with Authentik" })).toBeVisible();
    });

    test("native login keeps working next to OIDC, and the two can alternate", async ({ page }) => {
        await configureOIDC();
        await openLoginPage(page);

        await login(page);
        await expect(page.getByText("Add New Monitor")).toBeVisible();
        await logout(page);

        await loginWithOIDC(page);
        await logout(page);

        await login(page);
        await expect(page.getByText("Add New Monitor")).toBeVisible();
    });

    test("without Remember me the token stays in the session storage", async ({ page }) => {
        await configureOIDC();
        await openLoginPage(page);

        await page.getByLabel("Remember me").uncheck();
        await loginWithOIDC(page);

        expect(await page.evaluate(() => !!sessionStorage.token)).toBe(true);
        expect(await page.evaluate(() => !!localStorage.token)).toBe(false);
    });

    test("an identity without a linked account is refused", async ({ page }, testInfo) => {
        await configureOIDC({ linked: false });
        await openLoginPage(page);

        await page.getByRole("button", { name: "Login with Authentik" }).click();
        await expect(page.getByRole("alert")).toHaveText(
            "No account is linked to this identity. Contact the administrator."
        );
        expect(await page.evaluate(() => !!localStorage.token || !!sessionStorage.token)).toBe(false);
        await screenshot(testInfo, page);

        await page.getByRole("link", { name: "Back to login" }).click();
        await expect(page.getByRole("button", { name: "Log in" })).toBeVisible();
    });

    test("a forged login ticket is refused", async ({ page }) => {
        await configureOIDC();
        await page.goto("./oidc-callback#ticket=forged-ticket-value");

        await expect(page.getByRole("alert")).toHaveText(
            "This login link expired or was already used. Please try again."
        );
        expect(page.url()).not.toContain("forged");
    });

    test("an unknown error code is shown as a generic message, never as markup", async ({ page }) => {
        await page.goto("./oidc-callback#error=%3Cimg%20src%3Dx%20alt%3Dinjected%3E");

        await expect(page.getByRole("alert")).toHaveText("Login failed. Please try again.");
        await expect(page.locator("img[alt='injected']")).toHaveCount(0);
    });

    test("OIDC is off once it is disabled and native login still works", async ({ page, request }) => {
        await configureOIDC({ enabled: false });
        await openLoginPage(page);

        await expect(page.getByRole("button", { name: "Login with Authentik" })).toHaveCount(0);
        const response = await request.get("/auth/oidc/login", { maxRedirects: 0 });
        expect(response.status()).toBe(404);

        await login(page);
        await expect(page.getByText("Add New Monitor")).toBeVisible();
    });

    test("an invalid stored token shows the login page", async ({ page }) => {
        await configureOIDC();
        await page.addInitScript(() => localStorage.setItem("token", "not-a-valid-token"));
        await openLoginPage(page);

        await expect(page.getByRole("button", { name: "Login with Authentik" })).toBeVisible();
        expect(await page.evaluate(() => localStorage.token)).toBeUndefined();
    });
});

/**
 * Open the OIDC settings page as the admin.
 * @param {Page} page Page
 * @returns {Promise<void>}
 */
async function openSettings(page) {
    await page.goto("./settings/oidc");
    await login(page);
    await expect(page.getByTestId("oidc-status")).toBeVisible();
}

test.describe("OIDC settings", () => {
    test.beforeAll(async () => {
        await provider.start(PROVIDER_PORT);
    });

    test.afterAll(async () => {
        provider.stop();
        await restoreSqliteSnapshot();
    });

    test.beforeEach(async () => {
        await restoreSqliteSnapshot();
        provider.claims = {};
    });

    test("shows a disabled, empty configuration with the default redirect URI", async ({ page }, testInfo) => {
        await openSettings(page);

        await expect(page.getByTestId("oidc-status")).toHaveText("OIDC: Disabled");
        await expect(page.getByTestId("oidc-errors")).toContainText("Client ID is required");
        await expect(page.locator("#oidc-redirect-uri")).toHaveValue(`${url}/auth/oidc/callback`);
        await expect(page.getByTestId("oidc-not-linked")).toBeVisible();
        await screenshot(testInfo, page);
    });

    test("configures OIDC, signs in with it, then unlinks the account", async ({ page }, testInfo) => {
        provider.claims = { preferred_username: "admin" };
        await openSettings(page);

        await page.locator("#oidc-issuer").fill(provider.issuer);
        await page.getByTestId("oidc-test").click();
        await expect(page.getByTestId("oidc-test-result")).toContainText(`Connected to ${provider.issuer}`);

        await page.locator("#oidc-client-id").fill("kuma");
        await page.locator("#oidc-client-secret input").fill("secret");
        await page.locator("#oidc-auto-link").check();
        await page.getByLabel("Enable OIDC login").check();
        await page.locator("#oidc-current-password").fill("admin123");
        await screenshot(testInfo, page);
        await page.getByTestId("oidc-save").click();

        await expect(page.getByTestId("oidc-status")).toHaveText("OIDC: Enabled");
        // The secret is write-only
        await expect(page.locator("#oidc-client-secret input")).toHaveValue("");
        await expect(page.locator("#oidc-client-secret input")).toHaveAttribute("placeholder", "Unchanged");

        await logout(page);
        await loginWithOIDC(page);

        await page.goto("./settings/oidc");
        await expect(page.getByTestId("oidc-linked")).toContainText(provider.issuer);
        await screenshot(testInfo, page);

        await page.getByTestId("oidc-unlink").click();
        await page.locator("#oidc-unlink-password").fill("admin123");
        await page.locator(".modal").getByRole("button", { name: "Unlink" }).click();
        await expect(page.getByTestId("oidc-not-linked")).toBeVisible();
    });

    test("a wrong password does not enable OIDC", async ({ page }) => {
        await openSettings(page);

        await page.locator("#oidc-issuer").fill(provider.issuer);
        await page.locator("#oidc-client-id").fill("kuma");
        await page.locator("#oidc-client-secret input").fill("secret");
        await page.getByLabel("Enable OIDC login").check();
        await page.locator("#oidc-current-password").fill("not-the-password");
        await page.getByTestId("oidc-save").click();

        await expect(page.getByText("Incorrect current password")).toBeVisible();
        await expect(page.getByTestId("oidc-status")).toHaveText("OIDC: Disabled");
    });

    test("an incomplete configuration cannot be enabled", async ({ page }) => {
        await openSettings(page);

        await page.getByLabel("Enable OIDC login").check();
        await page.locator("#oidc-current-password").fill("admin123");
        await page.getByTestId("oidc-save").click();

        await expect(page.getByText("Invalid OIDC configuration")).toBeVisible();
        await expect(page.getByTestId("oidc-status")).toHaveText("OIDC: Disabled");
    });

    test("disabling OIDC needs no password", async ({ page }) => {
        await configureOIDC();
        await openSettings(page);
        await expect(page.getByTestId("oidc-status")).toHaveText("OIDC: Enabled");

        await page.getByLabel("Enable OIDC login").uncheck();
        await expect(page.locator("#oidc-current-password")).toHaveCount(0);
        await page.getByTestId("oidc-save").click();

        await expect(page.getByTestId("oidc-status")).toHaveText("OIDC: Disabled");
    });

    test("the connection test reports an unreachable provider", async ({ page }) => {
        await openSettings(page);

        await page.locator("#oidc-issuer").fill("http://127.0.0.1:1");
        await page.getByTestId("oidc-test").click();

        await expect(page.getByTestId("oidc-test-result")).toContainText("Could not reach the identity provider");
    });
});
