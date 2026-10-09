// OIDC: in-memory, single-use, expiring storage for pending logins and login tickets.
const crypto = require("crypto");

class ExpiringStore {
    entries = new Map();

    /**
     * @param {object} options Store options
     * @param {number} options.ttlMs Lifetime of an entry in milliseconds
     * @param {number} options.maxEntries Oldest entries are dropped beyond this size
     * @param {Function} options.now Clock, replaceable in tests
     */
    constructor({ ttlMs, maxEntries, now = Date.now }) {
        this.ttlMs = ttlMs;
        this.maxEntries = maxEntries;
        this.now = now;
    }

    /**
     * Store a value under a key.
     * @param {string} key Lookup key
     * @param {any} value Value to keep
     * @returns {string} The key
     */
    put(key, value) {
        this.prune();
        while (this.entries.size >= this.maxEntries) {
            this.entries.delete(this.entries.keys().next().value);
        }
        this.entries.set(key, { value, expires: this.now() + this.ttlMs });
        return key;
    }

    /**
     * Store a value under a new random key.
     * @param {any} value Value to keep
     * @returns {string} The generated key
     */
    putRandom(value) {
        return this.put(crypto.randomBytes(32).toString("base64url"), value);
    }

    /**
     * Remove and return a value. Each entry can be taken only once.
     * @param {any} key Lookup key
     * @returns {any} The value, or undefined if missing or expired
     */
    take(key) {
        if (typeof key !== "string") {
            return undefined;
        }
        const entry = this.entries.get(key);
        this.entries.delete(key);
        return entry && entry.expires > this.now() ? entry.value : undefined;
    }

    /**
     * Drop expired entries.
     * @returns {void}
     */
    prune() {
        const now = this.now();
        for (const [key, entry] of this.entries) {
            if (entry.expires <= now) {
                this.entries.delete(key);
            }
        }
    }
}

// Tickets are exchanged by the browser right after the callback redirect.
const oidcTickets = new ExpiringStore({ ttlMs: 60 * 1000, maxEntries: 100 });

module.exports = { ExpiringStore, oidcTickets };
