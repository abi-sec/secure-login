'use strict';

const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');

/**
 * Login rate limiter.
 * Blocks brute-force and credential stuffing attacks.
 * 5 attempts per 15 minutes per IP.
 */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  standardHeaders: true,   // Return rate limit info in RateLimit-* headers
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Only count failed requests

  handler: (req, res) => {
    logger.security('RATE_LIMIT_LOGIN', {
      ip: req.ip,
      username: req.body?.username || 'unknown',
    });
    res.status(429).render('login', {
      error: 'Too many login attempts. Please wait 15 minutes before trying again.',
      username: '',
    });
  },
});

/**
 * Registration rate limiter.
 * Prevents account enumeration at scale and mass account creation.
 * 3 registrations per hour per IP.
 */
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,

  handler: (req, res) => {
    logger.security('RATE_LIMIT_REGISTER', { ip: req.ip });
    res.status(429).render('login', {
      error: 'Too many registration attempts. Please try again later.',
      username: '',
    });
  },
});

/**
 * File upload rate limiter.
 * Prevents disk exhaustion DoS via repeated file uploads.
 * 10 uploads per 10 minutes per IP.
 */
const uploadLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,

  handler: (req, res) => {
    logger.security('RATE_LIMIT_UPLOAD', { ip: req.ip, userId: req.user?.id });
    res.status(429).render('feedback', {
      user: req.user,
      error: 'Too many uploads. Please wait before uploading again.',
      success: null,
    });
  },
});

/**
 * General API limiter — catch-all for all other routes.
 */
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = { loginLimiter, registerLimiter, uploadLimiter, generalLimiter };
