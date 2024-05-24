import { Knex, knex } from 'knex';
import knexTinyLogger from 'knex-tiny-logger';

import config from './knexfile';

const env = process.env.NODE_ENV;
const dbConfig1 = config.develsopment;
const dbConfig2 = config.development;

// if (env === "production") {
//   dbConfig1 = config.productionRead;
//   dbConfig2 = config.productionWrite;
// }

export const knexRead =
  env === 'production'
    ? (knex(dbConfig1) as Knex<Record<string, string>, unknown[]>)
    : (knexTinyLogger(knex(dbConfig1), {
        bindings: false,
        logger: console.debug,
      }) as Knex<Record<string, string>, unknown[]>);
export const knexWrite =
  env === 'production'
    ? (knex(dbConfig2) as Knex<Record<string, string>, unknown[]>)
    : (knexTinyLogger(knex(dbConfig2), {
        bindings: false,
        logger: console.debug,
      }) as Knex<Record<string, string>, unknown[]>);

// knex(dbConfig1).raw("SELECT 1").then(() => {
// console.log("PostgreSQL connected");
// })
// .catch((e) => {
// console.log("PostgreSQL not connected");
// console.error(e);
// });
