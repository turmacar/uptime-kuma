<template>
    <div>
        <div v-if="loaded" class="my-4">
            <p class="mb-3">
                {{ $t("oidcIntro") }}
                <span
                    class="badge ms-2"
                    :class="savedEnabled ? 'bg-primary' : 'bg-secondary'"
                    data-testid="oidc-status"
                >
                    {{ savedEnabled ? $t("oidcStatusEnabled") : $t("oidcStatusDisabled") }}
                </span>
            </p>

            <div v-if="errors.length > 0" class="alert alert-warning" role="alert" data-testid="oidc-errors">
                {{ $t("oidcIncomplete") }}
                <ul class="mb-0">
                    <li v-for="error in errors" :key="error">{{ error }}</li>
                </ul>
            </div>

            <form @submit.prevent="save">
                <div class="form-check form-switch mb-4">
                    <input id="oidc-enabled" v-model="form.enabled" class="form-check-input" type="checkbox" />
                    <label class="form-check-label" for="oidc-enabled">{{ $t("oidcEnable") }}</label>
                </div>

                <div class="mb-4">
                    <label for="oidc-issuer" class="form-label">{{ $t("oidcIssuer") }}</label>
                    <div class="input-group">
                        <input
                            id="oidc-issuer"
                            v-model="form.issuer"
                            type="url"
                            class="form-control"
                            placeholder="https://auth.example.com/application/o/uptime-kuma/"
                            data-testid="oidc-issuer"
                        />
                        <button
                            class="btn btn-outline-primary"
                            type="button"
                            :disabled="testing || !form.issuer"
                            data-testid="oidc-test"
                            @click="testConnection"
                        >
                            {{ testing ? $t("oidcTesting") : $t("oidcTestConnection") }}
                        </button>
                    </div>
                    <div class="form-text">{{ $t("oidcIssuerHelp") }}</div>

                    <div v-if="testResult" class="mt-2" data-testid="oidc-test-result">
                        <div v-if="testResult.ok" class="alert alert-success mb-2" role="alert">
                            {{ $t("oidcTestOk", { issuer: testResult.issuer }) }}
                        </div>
                        <div v-else class="alert alert-danger mb-2" role="alert">
                            {{ testResult.msg }}
                        </div>
                        <div
                            v-for="warning in testResult.warnings || []"
                            :key="warning"
                            class="alert alert-warning mb-2"
                            role="alert"
                        >
                            {{ warningText(warning, testResult) }}
                        </div>
                    </div>
                </div>

                <div class="mb-4">
                    <label for="oidc-client-id" class="form-label">{{ $t("oidcClientId") }}</label>
                    <input
                        id="oidc-client-id"
                        v-model="form.clientId"
                        type="text"
                        class="form-control"
                        autocomplete="off"
                        data-testid="oidc-client-id"
                    />
                </div>

                <div class="mb-4">
                    <label for="oidc-client-secret" class="form-label">{{ $t("oidcClientSecret") }}</label>
                    <HiddenInput
                        id="oidc-client-secret"
                        v-model="form.clientSecret"
                        :placeholder="hasClientSecret ? $t('oidcClientSecretUnchanged') : ''"
                        data-testid="oidc-client-secret"
                    />
                    <div class="form-text">{{ $t("oidcClientSecretHelp") }}</div>
                </div>

                <div class="mb-4">
                    <label for="oidc-redirect-uri" class="form-label">{{ $t("oidcRedirectUri") }}</label>
                    <CopyableInput id="oidc-redirect-uri" v-model="form.redirectUri" data-testid="oidc-redirect-uri" />
                    <div class="form-text">{{ $t("oidcRedirectUriHelp") }}</div>
                </div>

                <div class="mb-4">
                    <label for="oidc-scopes" class="form-label">{{ $t("oidcScopes") }}</label>
                    <input
                        id="oidc-scopes"
                        v-model="form.scopes"
                        type="text"
                        class="form-control"
                        placeholder="openid profile email"
                        data-testid="oidc-scopes"
                    />
                    <div class="form-text">{{ $t("oidcScopesHelp") }}</div>
                </div>

                <div class="form-check mb-1">
                    <input id="oidc-auto-link" v-model="form.autoLink" class="form-check-input" type="checkbox" />
                    <label class="form-check-label" for="oidc-auto-link">{{ $t("oidcAutoLink") }}</label>
                </div>
                <div class="form-text mb-3">{{ $t("oidcAutoLinkHelp") }}</div>

                <div class="form-check mb-1">
                    <input
                        id="oidc-require-email-verified"
                        v-model="form.requireEmailVerified"
                        class="form-check-input"
                        type="checkbox"
                    />
                    <label class="form-check-label" for="oidc-require-email-verified">
                        {{ $t("oidcRequireEmailVerified") }}
                    </label>
                </div>
                <div class="form-text mb-4">{{ $t("oidcRequireEmailVerifiedHelp") }}</div>

                <div v-if="form.enabled" class="mb-4">
                    <label for="oidc-current-password" class="form-label">{{ $t("Current Password") }}</label>
                    <input
                        id="oidc-current-password"
                        v-model="currentPassword"
                        type="password"
                        class="form-control"
                        autocomplete="current-password"
                        required
                        data-testid="oidc-current-password"
                    />
                    <div class="form-text">{{ $t("oidcCurrentPasswordHelp") }}</div>
                </div>

                <button class="btn btn-primary" type="submit" :disabled="saving" data-testid="oidc-save">
                    {{ $t("Save") }}
                </button>
            </form>

            <h5 class="mt-5 mb-3 settings-subheading">{{ $t("oidcAccount") }}</h5>
            <div v-if="info && info.linked" data-testid="oidc-linked">
                <p>
                    {{ $t("oidcLinkedTo", { issuer: info.issuer }) }}
                    <br />
                    <small v-if="info.lastLogin" class="text-muted">
                        {{ $t("oidcLastLogin", { time: $root.datetime(info.lastLogin) }) }}
                    </small>
                </p>
                <button
                    class="btn btn-outline-danger"
                    type="button"
                    data-testid="oidc-unlink"
                    @click="$refs.confirmUnlink.show()"
                >
                    {{ $t("oidcUnlink") }}
                </button>
            </div>
            <p v-else data-testid="oidc-not-linked">{{ $t("oidcNotLinked") }}</p>
        </div>

        <Confirm
            ref="confirmUnlink"
            btn-style="btn-danger"
            :yes-text="$t('oidcUnlink')"
            :no-text="$t('Leave')"
            @yes="unlink"
        >
            <p>{{ $t("oidcUnlinkConfirm") }}</p>
            <div class="mb-3">
                <label for="oidc-unlink-password" class="form-label">{{ $t("Current Password") }}</label>
                <input
                    id="oidc-unlink-password"
                    v-model="unlinkPassword"
                    type="password"
                    class="form-control"
                    autocomplete="current-password"
                    required
                    data-testid="oidc-unlink-password"
                />
            </div>
        </Confirm>
    </div>
</template>

<script>
import Confirm from "../Confirm.vue";
import CopyableInput from "../CopyableInput.vue";
import HiddenInput from "../HiddenInput.vue";

export default {
    components: {
        Confirm,
        CopyableInput,
        HiddenInput,
    },

    data() {
        return {
            loaded: false,
            form: {
                enabled: false,
                issuer: "",
                clientId: "",
                clientSecret: "",
                redirectUri: "",
                scopes: "openid profile email",
                autoLink: false,
                requireEmailVerified: false,
            },
            hasClientSecret: false,
            savedEnabled: false,
            errors: [],
            currentPassword: "",
            saving: false,
            testing: false,
            testResult: null,
            info: null,
            unlinkPassword: "",
        };
    },

    mounted() {
        this.load();
    },

    methods: {
        /**
         * Load the saved settings and the link status of this account
         * @returns {void}
         */
        load() {
            const socket = this.$root.getSocket();

            socket.emit("getOIDCSettings", (res) => {
                if (!res.ok) {
                    this.$root.toastRes(res);
                    return;
                }
                const config = res.config;
                this.form = {
                    enabled: config.enabled,
                    issuer: config.issuer,
                    clientId: config.clientId,
                    clientSecret: "",
                    redirectUri: config.redirectUri || `${this.$root.baseURL}/auth/oidc/callback`,
                    scopes: config.scopes.join(" "),
                    autoLink: config.autoLink,
                    requireEmailVerified: config.requireEmailVerified,
                };
                this.hasClientSecret = config.hasClientSecret;
                this.savedEnabled = config.enabled;
                this.errors = res.errors;
                this.loaded = true;
            });

            socket.emit("getOIDCInfo", (res) => {
                if (res.ok) {
                    this.info = res.info;
                }
            });
        },

        /**
         * Save the form. The current password is only sent (and needed) when OIDC is enabled.
         * @returns {void}
         */
        save() {
            this.saving = true;
            const payload = {
                ...this.form,
                issuer: this.form.issuer.trim(),
                redirectUri: this.form.redirectUri.trim(),
                scopes: this.form.scopes.split(/[\s,]+/).filter(Boolean),
            };

            this.$root
                .getSocket()
                .emit("setOIDCSettings", payload, this.form.enabled ? this.currentPassword : null, (res) => {
                    this.saving = false;
                    this.$root.toastRes(res);
                    if (res.ok) {
                        this.currentPassword = "";
                        this.testResult = null;
                        this.load();
                    }
                });
        },

        /**
         * Check that the issuer answers OpenID Connect discovery
         * @returns {void}
         */
        testConnection() {
            this.testing = true;
            this.testResult = null;
            this.$root.getSocket().emit("testOIDCConnection", this.form.issuer.trim(), (res) => {
                this.testing = false;
                this.testResult = res;
            });
        },

        /**
         * Text for a warning code from the connection test
         * @param {string} code Warning code
         * @param {object} result Result of the connection test
         * @returns {string} Translated text
         */
        warningText(code, result) {
            const keys = {
                issuer_mismatch: "oidcWarningIssuerMismatch",
                authorization_code_not_supported: "oidcWarningNoAuthorizationCode",
                pkce_not_supported: "oidcWarningNoPkce",
            };
            return this.$t(keys[code] ?? "oidcWarningUnknown", { issuer: result.issuer });
        },

        /**
         * Remove the link between this account and its OIDC identity
         * @returns {void}
         */
        unlink() {
            this.$root.getSocket().emit("unlinkOIDC", this.unlinkPassword, (res) => {
                this.$root.toastRes(res);
                this.unlinkPassword = "";
                if (res.ok) {
                    this.load();
                }
            });
        },
    },
};
</script>
