const { describe, test } = require("node:test");
const assert = require("node:assert");
const { ExpiringStore } = require("../../server/oidc-store");

describe("OIDC store", () => {
    /**
     * Store with a controllable clock.
     * @param {object} options Overrides
     * @returns {{store: ExpiringStore, clock: {now: number}}} Store and clock
     */
    function makeStore(options = {}) {
        const clock = { now: 1000 };
        const store = new ExpiringStore({ ttlMs: 100, maxEntries: 3, now: () => clock.now, ...options });
        return { store, clock };
    }

    test("an entry can be taken once", () => {
        const { store } = makeStore();
        store.put("a", 1);
        assert.strictEqual(store.take("a"), 1);
        assert.strictEqual(store.take("a"), undefined);
    });

    test("expired entries are not returned", () => {
        const { store, clock } = makeStore();
        store.put("a", 1);
        clock.now += 100;
        assert.strictEqual(store.take("a"), undefined);
    });

    test("entries just before expiry are returned", () => {
        const { store, clock } = makeStore();
        store.put("a", 1);
        clock.now += 99;
        assert.strictEqual(store.take("a"), 1);
    });

    test("the oldest entry is dropped beyond the size limit", () => {
        const { store } = makeStore();
        ["a", "b", "c", "d"].forEach((k) => store.put(k, k));
        assert.strictEqual(store.take("a"), undefined);
        assert.strictEqual(store.take("d"), "d");
        assert.ok(store.entries.size <= 3);
    });

    test("expired entries are pruned on put", () => {
        const { store, clock } = makeStore();
        store.put("a", 1);
        store.put("b", 2);
        clock.now += 200;
        store.put("c", 3);
        assert.strictEqual(store.entries.size, 1);
    });

    test("non-string keys never match", () => {
        const { store } = makeStore();
        store.put("a", 1);
        assert.strictEqual(store.take(["a"]), undefined);
        assert.strictEqual(store.take(undefined), undefined);
        assert.strictEqual(store.take({ toString: () => "a" }), undefined);
    });

    test("random keys are unique and unguessable in length", () => {
        const { store } = makeStore({ maxEntries: 10 });
        const a = store.putRandom(1);
        const b = store.putRandom(2);
        assert.notStrictEqual(a, b);
        assert.ok(a.length >= 43);
        assert.strictEqual(store.take(a), 1);
    });
});
