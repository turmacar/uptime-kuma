// OIDC: link a user to one external identity (issuer + subject). All columns are optional.
exports.up = async function (knex) {
    await knex.schema.alterTable("user", function (table) {
        table.string("oidc_sub", 255).nullable().defaultTo(null);
        table.string("oidc_issuer", 255).nullable().defaultTo(null);
        table.datetime("last_oidc_login").nullable().defaultTo(null);
    });

    await knex.schema.alterTable("user", function (table) {
        table.unique(["oidc_issuer", "oidc_sub"], { indexName: "user_oidc_identity" });
    });
};

exports.down = async function (knex) {
    await knex.schema.alterTable("user", function (table) {
        table.dropUnique(["oidc_issuer", "oidc_sub"], "user_oidc_identity");
    });

    await knex.schema.alterTable("user", function (table) {
        table.dropColumn("oidc_sub");
        table.dropColumn("oidc_issuer");
        table.dropColumn("last_oidc_login");
    });
};
