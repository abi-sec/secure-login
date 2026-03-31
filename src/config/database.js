'use strict';

const { Sequelize } = require('sequelize');
const logger = require('../utils/logger');

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.APP_DB_USER || process.env.DB_USER,
  process.env.APP_DB_PASSWORD || process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 5432,
    dialect: 'postgres',

    // Restrict connection pool — limits blast radius of a DoS
    pool: {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000,
    },

    // Log queries only in development — never log queries in production
    // as they may contain sensitive parameterized data fragments
    logging: process.env.NODE_ENV === 'development'
      ? (msg) => logger.debug({ event: 'DB_QUERY', msg })
      : false,

    dialectOptions: {
      // Enforce SSL in production
      ssl: process.env.NODE_ENV === 'production'
        ? { require: true, rejectUnauthorized: true }
        : false,

      // Statement timeout: kills queries running longer than 5s
      // Mitigates Event Loop blocking from expensive DB calls
      statement_timeout: 5000,
    },
  }
);

/**
 * Test the database connection on startup.
 * Exits the process if the DB is unreachable — fail fast, fail loud.
 */
async function connectDB() {
  try {
    await sequelize.authenticate();
    logger.security('DB_CONNECTED', { host: process.env.DB_HOST });
  } catch (err) {
    logger.error({ event: 'DB_CONNECTION_FAILED', error: err.message });
    process.exit(1);
  }
}

module.exports = { sequelize, connectDB };
