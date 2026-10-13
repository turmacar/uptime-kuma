<template>
    <div class="form-container" data-cy="oidc-callback">
        <div class="form">
            <div>
                <object width="64" height="64" data="/icon.svg" />
                <div style="font-size: 28px; font-weight: bold; margin-top: 5px">Uptime Kuma</div>
            </div>

            <div v-if="errorCode" class="mt-4">
                <div class="alert alert-danger" role="alert" data-cy="oidc-callback-error">
                    {{ $t(errorMessageKey) }}
                </div>
                <a
                    v-if="verifyEmailUrl"
                    :href="verifyEmailUrl"
                    rel="noopener noreferrer"
                    class="w-100 btn btn-outline-primary mb-2"
                    data-cy="oidc-verify-email"
                >
                    {{ $t("oidcVerifyEmail") }}
                </a>
                <router-link to="/dashboard" class="w-100 btn btn-primary">
                    {{ $t("oidcBackToLogin") }}
                </router-link>
            </div>

            <template v-else>
                <p class="mt-4">{{ $t("oidcAuthenticating") }}</p>
                <div v-if="$root.connectionErrorMsg" class="alert alert-warning" role="alert">
                    {{ $root.connectionErrorMsg }}
                </div>
            </template>
        </div>
    </div>
</template>

<script>
import axios from "axios";

// Codes come from the server redirect (`#error=<code>`); anything else is shown as "unknown".
const ERROR_MESSAGES = {
    no_session: "oidcErrorNoSession",
    no_account: "oidcErrorNoAccount",
    already_linked: "oidcErrorAlreadyLinked",
    password_required: "oidcErrorPasswordRequired",
    provider_error: "oidcErrorProvider",
    invalid_callback: "oidcErrorInvalidCallback",
    no_sub: "oidcErrorInvalidCallback",
    email_not_verified: "oidcErrorEmailNotVerified",
    discovery_failed: "oidcErrorDiscovery",
    server_error: "oidcErrorServer",
    invalid_ticket: "oidcErrorInvalidTicket",
    unknown: "oidcErrorUnknown",
};

export default {
    data() {
        return {
            ticket: null,
            errorCode: null,
            redeemed: false,
            verifyEmailUrl: null,
        };
    },

    computed: {
        connected() {
            return this.$root.socket.connected;
        },

        errorMessageKey() {
            return ERROR_MESSAGES[this.errorCode] ?? ERROR_MESSAGES.unknown;
        },
    },

    watch: {
        connected(connected) {
            if (connected) {
                this.redeem();
            }
        },
    },

    mounted() {
        const params = new URLSearchParams(this.$route.hash.slice(1));

        // The ticket is single use, but should not stay in the address bar or history
        this.$router.replace({ path: this.$route.path });

        const error = params.get("error");
        const ticket = params.get("ticket");

        if (error) {
            this.errorCode = error;
            if (error === "email_not_verified") {
                this.loadVerifyEmailUrl();
            }
            return;
        }
        if (!ticket) {
            this.errorCode = "unknown";
            return;
        }

        // Keep an old token from triggering its own login (and logout) alongside this one
        this.$root.storage().removeItem("token");

        this.ticket = ticket;
        if (this.connected) {
            this.redeem();
        }
    },

    methods: {
        /**
         * Fetch the optional link to the provider's email verification page. Only http(s) links are used.
         * @returns {Promise<void>}
         */
        async loadVerifyEmailUrl() {
            try {
                const res = await axios.get("/auth/oidc/status");
                const url = new URL(res.data?.verifyEmailUrl);
                if (url.protocol === "https:" || url.protocol === "http:") {
                    this.verifyEmailUrl = url.href;
                }
            } catch (e) {
                this.verifyEmailUrl = null;
            }
        },

        /**
         * Exchange the ticket for a login, once
         * @returns {void}
         */
        redeem() {
            if (!this.ticket || this.redeemed) {
                return;
            }
            this.redeemed = true;

            this.$root.loginByOIDCTicket(this.ticket, (res) => {
                this.ticket = null;

                if (res.ok) {
                    this.$router.replace("/dashboard");
                } else {
                    this.errorCode = res.msg === "authInvalidToken" ? "invalid_ticket" : "unknown";
                }
            });
        },
    },
};
</script>

<style lang="scss" scoped>
.form-container {
    display: flex;
    align-items: center;
    padding-top: 40px;
    padding-bottom: 40px;
}

.form {
    width: 100%;
    max-width: 330px;
    padding: 15px;
    margin: auto;
    text-align: center;
}
</style>
