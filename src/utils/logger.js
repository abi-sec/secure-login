'use strict';

const { createLogger, format, transports } = require('winston');
const { combine, timestamp, json, errors } = format;

/**
 * Structured audit logger.
 * All security events are written as JSON — easy to pipe into
 * SIEM tools or grep for specific event types.
 *
 * IMPORTANT: This logger must NEVER log plaintext passwords,
 * session tokens, or raw PII. Callers are responsible for
 * sanitizing data before passing it here.
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
    // All logs → combined.log
    new transports.File({ filename: 'logs/combined.log' }),
    // Error and above → error.log
    new transports.File({ filename: 'logs/error.log', level: 'error' }),
  ],
});

// In development, also print to console in readable format
if (process.env.NODE_ENV !== 'production') {
  logger.add(new transports.Console({
    format: format.combine(
      format.colorize(),
      format.simple()
    )
  }));
}

/**
 * Log a security-relevant event.
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
};

module.exports = logger;
