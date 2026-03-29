'use strict';

const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Feedback = require('../models/Feedback');
const logger = require('../utils/logger');
const { requireAuth, requireRole } = require('../middleware/rbac');
const { registerLimiter } = require('../middleware/rateLimiter');
const path = require('path');
const fs = require('fs');

const router = express.Router();

// ─── Helper: fetch all users and feedback for re-render ──────────────────────
async function getAdminData() {
  const users = await User.findAll({
    attributes: ['id', 'username', 'role', 'failedLoginAttempts', 'lockedUntil', 'createdAt'],
    order: [['createdAt', 'DESC']],
  });
  const feedbacks = await Feedback.findAll({
    include: [{ model: User, attributes: ['username'] }],
    order: [['createdAt', 'DESC']],
  });
  return { users, feedbacks };
}

// ─── GET /admin ───────────────────────────────────────────────────────────────
router.get('/admin', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { users, feedbacks } = await getAdminData();
    res.render('admin', { user: req.user, users, feedbacks, error: null, success: null });
  } catch (err) {
    logger.error({ event: 'ADMIN_LOAD_ERROR', error: err.message });
    res.status(500).render('error', { message: 'Could not load admin panel.', status: 500 });
  }
});

// ─── POST /admin/add-user ─────────────────────────────────────────────────────
router.post('/admin/add-user',
  requireAuth,
  requireRole('admin'),
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
    body('password')
      .isLength({ min: 10 }).withMessage('Password must be at least 10 characters.')
      .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter.')
      .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter.')
      .matches(/[0-9]/).withMessage('Password must contain at least one number.')
      .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character.'),
    body('role')
      .isIn(['user', 'admin']).withMessage('Invalid role.'),
  ],
  async (req, res) => {
    const rerender = async (error) => {
      const { users, feedbacks } = await getAdminData();
      return res.status(400).render('admin', { user: req.user, users, feedbacks, error, success: null });
    };

    const errors = validationResult(req);
    if (!errors.isEmpty()) return rerender(errors.array()[0].msg);

    try {
      const { username, email, password, role } = req.body;

      const existing = await User.findOne({ where: { username } });
      if (existing) return rerender('Username already exists. Please choose a different one.');

      const passwordHash = await User.hashPassword(password);
      const newUser = await User.create({ username, passwordHash, role });
      newUser.setEmail(email);
      await newUser.save();

      logger.security('ADMIN_USER_CREATED', {
        adminId: req.user.id,
        newUsername: username,
        role,
      });

      const { users, feedbacks } = await getAdminData();
      res.render('admin', {
        user: req.user, users, feedbacks,
        error: null,
        success: `User "${username}" created successfully with role "${role}".`,
      });

    } catch (err) {
      logger.error({ event: 'ADMIN_ADD_USER_ERROR', error: err.message });
      return rerender('Failed to create user. Please try again.');
    }
  }
);

// ─── POST /admin/delete-user ──────────────────────────────────────────────────
router.post('/admin/delete-user',
  requireAuth,
  requireRole('admin'),
  async (req, res) => {
    const rerender = async (error) => {
      const { users, feedbacks } = await getAdminData();
      return res.status(400).render('admin', { user: req.user, users, feedbacks, error, success: null });
    };

    try {
      const { userId } = req.body;

      if (userId === req.user.id) return rerender('You cannot delete your own account.');

      const target = await User.findByPk(userId);
      if (!target) return rerender('User not found.');

      await target.destroy();

      logger.security('ADMIN_USER_DELETED', {
        adminId: req.user.id,
        deletedUserId: userId,
        deletedUsername: target.username,
      });

      const { users, feedbacks } = await getAdminData();
      res.render('admin', {
        user: req.user, users, feedbacks,
        error: null,
        success: `User "${target.username}" deleted successfully.`,
      });

    } catch (err) {
      logger.error({ event: 'ADMIN_DELETE_USER_ERROR', error: err.message });
      return rerender('Failed to delete user. Please try again.');
    }
  }
);

// ─── GET /admin/download/:uuid ────────────────────────────────────────────────
// Admin can download uploaded files — UUID lookup prevents path traversal
router.get('/admin/download/:uuid',
  requireAuth,
  requireRole('admin'),
  async (req, res) => {
    try {
      const { uuid } = req.params;

      // Validate UUID format before touching filesystem
      const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      if (!UUID_REGEX.test(uuid)) {
        return res.status(400).render('error', { message: 'Invalid file identifier.', status: 400 });
      }

      // Look up in DB to confirm this UUID exists and get original filename
      const feedback = await Feedback.findOne({ where: { fileUuid: uuid } });
      if (!feedback) {
        return res.status(404).render('error', { message: 'File not found.', status: 404 });
      }

      const uploadDir = process.env.UPLOAD_DIR || 'uploads';
      const filePath = path.join(process.cwd(), uploadDir, uuid);

      if (!fs.existsSync(filePath)) {
        return res.status(404).render('error', { message: 'File not found on disk.', status: 404 });
      }

      logger.security('ADMIN_FILE_DOWNLOAD', {
        adminId: req.user.id,
        fileUuid: uuid,
        feedbackId: feedback.id,
      });

      res.download(filePath, feedback.originalFilename || uuid);

    } catch (err) {
      logger.error({ event: 'ADMIN_DOWNLOAD_ERROR', error: err.message });
      res.status(500).render('error', { message: 'Could not download file.', status: 500 });
    }
  }
);

module.exports = router;