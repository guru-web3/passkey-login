exports.up = function (knex) {
  return knex.schema.createTable(
    'global_wallet_passkey_credentials',
    (table) => {
      table.string('credential_id', 255).notNullable();
      table.string('passkey_user_id', 255).notNullable(); // Project ID
      table.string('public_key', 255).nullable(); // Project ID
      table.string('counter', 255).nullable(); // Project ID
      table.string('pubKey', 255).nullable(); // Project ID

      table.timestamp('created_at').notNullable().defaultTo(knex.fn.now()); // Creation timestamp
      table.timestamp('updated_at').notNullable().defaultTo(knex.fn.now()); // Update timestamp
    }
  );
};

exports.down = function (knex) {
  return knex.schema.dropTableIfExists('global_wallet_passkey_credentials');
};
