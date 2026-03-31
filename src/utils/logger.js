'use strict';

const { createLogger, format, transports } = require('winston');
const { combine, timestamp, json, errors } = format;

/**
 * Structured audit logger.
 * All security events are written as JSON so its easy to pipe into
 * SIEM tools or grep for specific event types.
 *
 * IMPORTANT: This logger must NEVER log plaintext passwords,
 * session tokens, or raw PII. So make sure to sanitize data before passing it here.
 */
const logger = createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: combine(
    timestamp({ format: 'ISO' }),
    errors({ stack: true }),
    json()
  ),
  defaultMeta: { service: 'loginapp' },
  transports: [
    // All logs -> combined.log
    new transports.File({ filename: 'logs/combined.log' }),
    // Error and above -> error.log
    new transports.File({ filename: 'logs/error.log', level: 'error' }),
  ],
});

// In development, also print to console in readable format
if (process.env.NODE_ENV !== 'production') {
  logger.add(new transports.Console({
    format: format.combine(
      format.colorize(),
      format.timestamp({ format: 'ISO' }),
      format.errors({ stack: true }),
      format.json()
    )
  }));
}

/**
 * Log a security-relevant event
 *
 * @param {string} event   - Machine-readable event type (e.g. 'LOGIN_FAILURE')
 * @param {object} meta    - Contextual data. Never include passwords or tokens.
 */
logger.security = function (event, meta = {}) {
  // Strip any accidental password fields before logging
  const safe = { ...meta };
  delete safe.password;
  delete safe.token;
  delete safe.secret;

  logger.info({ event, ...safe });

  // Write to database audit log asynchronously
  setTimeout(async () => {
    try {
      const AuditLog = require('../models/AuditLog');
      await AuditLog.create({
        event: event,
        userId: safe.userId || safe.moderatorId || null,
        ipAddress: safe.ip || null,
        details: safe
      });
    } catch (err) {
      // Fallback logging if DB is down or model not fully loaded yet
      logger.error({ event: 'AUDIT_DB_INSERT_FAILED', error: err.message });
    }
  });
};

module.exports = logger;
