'use strict';

const express = require('express');
const passport = require('../config/passport');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const logger = require('../utils/logger');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimiter');
const { requireAuth } = require('../middleware/rbac');

const router = express.Router();

const PASSWORD_VALIDATORS = [
  body('password')
    .isLength({ min: 10 })
    .withMessage('Password must be at least 10 characters.')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter.')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter.')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number.')
    .matches(/[^A-Za-z0-9]/)
    .withMessage('Password must contain at least one special character.'),
];

// ─── GET /login ───────────────────────────────────────────────────────────────
router.get('/login', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/home');
  res.render('login', { error: null, username: '' });
});

// ─── POST /login ──────────────────────────────────────────────────────────────
router.post('/login',
  loginLimiter,
  [
    body('username')
      .trim()
      .matches(/^[a-zA-Z0-9_]+$/).withMessage('Invalid username.')
      .isLength({ min: 3, max: 64 }),
    body('password')
      .notEmpty().withMessage('Password is required.')
      .isLength({ max: 128 }),
  ],
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('login', {
        error: errors.array()[0].msg,
        username: req.body.username || '',
      });
    }
    next();
  },
  (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
      if (err) return next(err);
      if (!user) {
        return res.status(401).render('login', {
          error: info?.message || 'Invalid credentials.',
          username: req.body.username || '',
        });
      }
      req.logIn(user, (err) => {
        if (err) return next(err);
        if (user.role === 'admin') return res.redirect('/admin');
        if (user.role === 'moderator') return res.redirect('/moderator');
        return res.redirect('/home');
      });
    })(req, res, next);
  },
  // eslint-disable-next-line no-unused-vars
  (err, req, res, _next) => {
    logger.error({ event: 'LOGIN_MIDDLEWARE_ERROR', error: err.message });
    res.status(500).render('login', { error: 'An error occurred. Please try again.', username: '' });
  }
);

// ─── GET /register ────────────────────────────────────────────────────────────
router.get('/register', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/home');
  res.render('register', { errors: [], formData: {} });
});

// ─── POST /register ───────────────────────────────────────────────────────────
router.post('/register',
  registerLimiter,
  [
    body('username')
      .trim()
      .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username may only contain letters, numbers, and underscores.')
      .isLength({ min: 3, max: 64 }).withMessage('Username must be 3–64 characters.'),
    body('email')
      .trim()
      .isEmail().withMessage('Please enter a valid email address.')
      .normalizeEmail(),
    ...PASSWORD_VALIDATORS,
    body('confirmPassword')
      .custom((value, { req }) => value === req.body.password)
      .withMessage('Passwords do not match.'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('register', {
        errors: errors.array(),
        formData: { username: req.body.username, email: req.body.email },
      });
    }

    try {
      const { username, email, password } = req.body;

      const existing = await User.findOne({ where: { username } });
      if (existing) {
        return res.status(400).render('register', {
          errors: [{ msg: 'Registration failed. Please choose different credentials.' }],
          formData: { username: '', email: '' },
        });
      }

      const passwordHash = await User.hashPassword(password);
      const user = await User.create({ username, passwordHash });
      user.setEmail(email);
      await user.save();

      logger.security('USER_REGISTERED', { username, userId: user.id });
      res.redirect('/login');

    } catch (err) {
      logger.error({ event: 'REGISTER_ERROR', error: err.message });
      res.status(500).render('register', {
        errors: [{ msg: 'Registration failed. Please try again.' }],
        formData: {},
      });
    }
  }
);

// ─── GET /account ─────────────────────────────────────────────────────────────
router.get('/account', requireAuth, (req, res) => {
  res.render('account', {
    user: req.user,
    passwordError: null,
    passwordSuccess: null,
  });
});

// ─── POST /change-password ────────────────────────────────────────────────────
router.post('/change-password',
  requireAuth,
  [
    body('currentPassword').notEmpty().withMessage('Current password required.'),
    ...PASSWORD_VALIDATORS,
    body('confirmPassword')
      .custom((value, { req }) => value === req.body.password)
      .withMessage('New passwords do not match.'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('account', {
        user: req.user,
        passwordError: errors.array()[0].msg,
        passwordSuccess: null,
      });
    }

    try {
      const user = await User.findByPk(req.user.id);
      const valid = await user.verifyPassword(req.body.currentPassword);

      if (!valid) {
        logger.security('PASSWORD_CHANGE_WRONG_CURRENT', { userId: req.user.id });
        return res.status(400).render('account', {
          user: req.user,
          passwordError: 'Current password is incorrect.',
          passwordSuccess: null,
        });
      }

      user.passwordHash = await User.hashPassword(req.body.password);
      await user.save();

      logger.security('PASSWORD_CHANGED', { userId: req.user.id });
      res.render('account', {
        user: req.user,
        passwordError: null,
        passwordSuccess: 'Password changed successfully.',
      });

    } catch (err) {
      logger.error({ event: 'PASSWORD_CHANGE_ERROR', error: err.message });
      res.status(500).render('account', {
        user: req.user,
        passwordError: 'An error occurred. Please try again.',
        passwordSuccess: null,
      });
    }
  }
);

// ─── POST /logout ─────────────────────────────────────────────────────────────
router.post('/logout', requireAuth, (req, res, next) => {
  const userId = req.user?.id;
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => {
      logger.security('LOGOUT', { userId });
      res.clearCookie('connect.sid');
      res.redirect('/login');
    });
  });
});

module.exports = router;