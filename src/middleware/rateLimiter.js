'use strict';

const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');

// Login rate limiter
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500,
  standardHeaders: true,   // Return rate limit info in RateLimit headers
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

// Registration rate limiter
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 300,
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

// Upload rate limiter
const uploadLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 100,
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

// General rate limiter for all other routes
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 2000,
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = { loginLimiter, registerLimiter, uploadLimiter, generalLimiter };
