exports.up = function (knex) {
  return knex.schema.createTable('global_wallet_passkey_users', (table) => {
    table.string('passkey_user_id').unique();
    table.string('username');
    table.timestamps();
  });
};

exports.down = function (knex) {
  return knex.schema.dropTable('global_wallet_passkey_users');
};
