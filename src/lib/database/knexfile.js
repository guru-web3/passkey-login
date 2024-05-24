module.exports = {
  development: {
    client: 'mysql2',
    connection: {
      host: process.env.RDS_HOSTNAME_WRITE,
      database: process.env.RDS_DB_NAME,
      port: process.env.RDS_PORT,
      user: process.env.RDS_USERNAME,
      password: process.env.RDS_PASSWORD,
      supportBigNumbers: true,
      bigNumberStrings: true,
    },
  },
};
