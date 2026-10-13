# OIDC login (turmacar fork)

This fork can let people sign in to Uptime Kuma through an OpenID Connect (OIDC) provider. It was built and tested for [Authentik](https://goauthentik.io/), but it uses standard OIDC discovery, so other providers that follow the spec should work.

Username and password login is not replaced. It always stays available as a way in when the provider is down or misconfigured.

## How it works

1. On the login page, the "Login with Authentik" button appears when OIDC is enabled and valid.
2. Clicking it sends the browser to the provider (authorization code flow with PKCE, `state` and `nonce`).
3. The provider sends the browser back to `/auth/oidc/callback`. Kuma checks `state`, a cookie that ties the login to that browser, and the ID token (signature, issuer, audience, expiry, nonce).
4. Kuma looks up the Kuma user that is linked to the identity (see [Linking accounts](#linking-accounts)).
5. The browser receives a single-use ticket (valid for 60 seconds) in the URL fragment and exchanges it over the socket for the same login token a password login produces.

No account is ever created by OIDC. A person can only sign in if an existing Kuma user is linked to their identity.

## Set up with Authentik

At Authentik:

1. Create an **OAuth2/OpenID Provider** (Applications, Providers).
2. Client type: **Confidential**. Note the client ID and the client secret.
3. Redirect URIs: add exactly `https://<your-kuma-host>/auth/oidc/callback` with strict matching. It must be the same string you enter in Kuma, including `http` or `https` and the port if any.
4. Scopes: the defaults `openid`, `profile` and `email` are enough.
5. **Signing key**: select one (for example the self-signed certificate). Without a signing key Authentik signs ID tokens with the client secret (HS256), and Kuma rejects them (it expects RS256).
6. Create an **Application** that uses the provider and note its slug.
7. Copy the **OpenID Configuration Issuer** from the provider page. It looks like `https://auth.example.com/application/o/<slug>/`. Keep the trailing slash.

In Kuma (Settings, OIDC):

1. Enter the **Issuer URL** and click **Test connection**. It should report the issuer it connected to. A warning that the provider reports a different issuer means you should use the value it shows.
2. Enter the **Client ID** and **Client Secret**.
3. Check the **Redirect URI** (prefilled with this site's address). Change it if users reach Kuma under a different address, and make it match the provider exactly.
4. Switch on **Enable OIDC login**, enter your **current password** and **Save**. The status badge changes to "OIDC: Enabled".

## Settings

| Setting                   | Meaning                                                                                                                                                                                                     |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Enable OIDC login         | Shows the login button and turns the endpoints on. Needs the current password to turn on.                                                                                                                   |
| Issuer URL                | Where Kuma discovers the provider's endpoints and signing keys. Must be `https`, except for `localhost` addresses.                                                                                          |
| Client ID, Client Secret  | From the provider. The secret is never shown again after saving. Leave it empty to keep the saved one.                                                                                                      |
| Redirect URI              | The callback URL the provider sends the browser back to. Must match the provider's setting.                                                                                                                 |
| Scopes                    | Space or comma separated. `openid` is always included.                                                                                                                                                      |
| Link accounts by username | See below. Meant for the first sign-in only.                                                                                                                                                                |
| Require a verified email  | Refuses sign-ins where the provider does not report `email_verified` as true. Check that your provider sends it before turning this on. Without it, such sign-ins are allowed and only logged as a warning. |
| Email verification link   | Optional. Shown as a button on the error page when a sign-in is refused because the email is not verified, for example the provider's user settings page. Only http(s) links are accepted.                  |

While OIDC is enabled, changing any of these settings needs the current password. Turning OIDC off does not.

## Linking accounts

A sign-in works when a Kuma user is linked to the identity (issuer plus subject). Two ways to link:

- **Automatically by username.** Turn on "Link accounts by username", then sign in with OIDC once. If the provider's `preferred_username` equals the Kuma username (exactly, same letter case), that Kuma user is linked to the identity. The Kuma user must have a password, must not be linked to another identity already, and must be active. Turn the setting off again afterwards.
- **Not at all.** Without the setting, an identity that is not linked is refused with "No account is linked to this identity".

Settings, OIDC, "Your account" shows whether the signed-in user is linked and when they last signed in with OIDC. **Unlink** removes the link (it asks for the password). Do this when the person was recreated at the provider and got a new subject.

Each Kuma user can be linked to one identity, and each identity to one Kuma user.

## Security notes

- **Automatic linking trusts the provider's username.** Anyone who can choose or change their username at the provider could take over the matching Kuma account while the setting is on. Use it for the first sign-in only.
- **Tokens do not expire.** An OIDC sign-in gives the same login token as a password sign-in, which never expires and does not depend on the provider session. Disabling or deleting a person at the provider does not sign them out of Kuma. To end such a session, change that Kuma user's password or deactivate the user in Kuma.
- **Two-factor authentication.** An OIDC sign-in does not ask for Kuma's own 2FA code. Let the provider enforce multi-factor authentication.
- **The client secret is stored in plain text** in the settings table (type `oidc`), like other Kuma secrets. It is never sent to the browser and never written to the log.
- **Rate limit.** The OIDC endpoints allow 30 requests per minute in total, separate from the password login limit.
- **Logging.** Every OIDC step is logged with the client IP, for example `[OIDC] WARN: Login failed (no_account): ... IP=203.0.113.7`. Secrets, `state`, codes and tickets are never logged.

## Limits

- One provider only.
- No account creation, no group or role mapping, and no sign-out at the provider when you log out of Kuma. Because the provider session stays active, clicking "Login with Authentik" right after logging out signs you straight back in.
- The button label is fixed ("Login with Authentik").
- The login flow needs the built web interface served by Kuma itself. It does not work from the Vite dev server on port 3000.

## Troubleshooting

When a sign-in fails, the page shows a message and the Kuma log has a line starting with `[OIDC]`, with a code in brackets.

| Message                                                 | Code                         | Usual cause                                                                                                                                                                                                                                                               |
| ------------------------------------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Your login session expired.                             | `no_session`                 | The browser did not send back the login cookie. Most often Kuma was opened under a different address than the Redirect URI (for example by IP instead of the domain). Also: the login took more than 10 minutes, Kuma restarted during the login, or cookies are blocked. |
| No account is linked to this identity.                  | `no_account`                 | Nobody is linked to this identity. Turn on "Link accounts by username" for one sign-in, or check that the provider's username equals the Kuma username.                                                                                                                   |
| This account is already linked to a different identity. | `already_linked`             | The matching Kuma user is linked to another identity. Unlink it in Settings, OIDC first.                                                                                                                                                                                  |
| Set a password for this account before linking it.      | `password_required`          | The matching Kuma user has no password.                                                                                                                                                                                                                                   |
| The identity provider rejected the login.               | `provider_error`             | The provider returned an error, for example access denied for this person. The log line shows the provider's error.                                                                                                                                                       |
| Authentication failed.                                  | `invalid_callback`, `no_sub` | The ID token or the code exchange was rejected. Check the log line: wrong client secret, redirect URI mismatch, ID token not signed with RS256 (select a signing key at the provider), or the server clock is more than a few seconds off.                                |
| Your email address is not verified.                     | `email_not_verified`         | "Require a verified email" is on and the provider does not report the email as verified. If an email verification link is set, the page offers it as a button.                                                                                                            |
| Could not reach the identity provider.                  | `discovery_failed`           | The Kuma server (not the browser) cannot reach the issuer URL. Check DNS, the Docker network and the TLS certificate.                                                                                                                                                     |
| Something went wrong.                                   | `server_error`               | Unexpected error. See the log line.                                                                                                                                                                                                                                       |
| This login link expired or was already used.            |                              | The one-time ticket was used twice, or more than 60 seconds passed. Sign in again.                                                                                                                                                                                        |

Other symptoms:

- **No button on the login page.** OIDC is off, or its settings are incomplete. Settings, OIDC lists what is missing.
- **`/auth/oidc/login` returns 404.** OIDC is disabled.
- **429 Too many requests.** The OIDC rate limit was hit. Wait a minute.
- **Locked out because of OIDC.** Sign in with your Kuma password. If you cannot reach the settings page, turn OIDC off in the database: `UPDATE setting SET value = 'false' WHERE key = 'oidc_enabled';` (on MariaDB write `` `key` `` with backticks).
