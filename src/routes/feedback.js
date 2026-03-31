'use strict';

const express = require('express');
const { body, validationResult } = require('express-validator');
const Feedback = require('../models/Feedback');
const User = require('../models/User');
const Listing = require('../models/Listing');
const logger = require('../utils/logger');
const { requireAuth, requireRole } = require('../middleware/rbac');
const { uploadLimiter } = require('../middleware/rateLimiter');
const { upload, validateFileSignature } = require('../middleware/fileValidator');
const path = require('path');
const fs = require('fs');

const router = express.Router();

// ─── GET /feedback ────────────────────────────────────────────────────────────
router.get('/feedback', requireAuth, (req, res) => {
  res.render('feedback', {
    user: req.user,
    error: null,
    success: null,
    passwordError: null,
    passwordSuccess: null,
  });
});

// ─── POST /feedback ───────────────────────────────────────────────────────────
router.post('/feedback',
  requireAuth,
  uploadLimiter,

  (req, res, next) => {
    upload.single('attachment')(req, res, (err) => {
      if (err) {
        logger.security('UPLOAD_MULTER_ERROR', {
          userId: req.user?.id,
          error: err.message,
        });
        return res.status(400).render('feedback', {
          user: req.user,
          error: err.message,
          success: null,
          passwordError: null,
          passwordSuccess: null,
        });
      }
      next();
    });
  },

  validateFileSignature,

  [
    body('message')
      .trim()
      .matches(/^[a-zA-Z0-9 .,!?'\-\n\r@#()]+$/)
      .withMessage('Message contains invalid characters.')
      .isLength({ min: 1, max: 2000 })
      .withMessage('Message must be between 1 and 2000 characters.')
      .escape(),
  ],

  async (req, res) => {
    if (req.uploadError) {
      return res.status(400).render('feedback', {
        user: req.user,
        error: req.uploadError,
        success: null,
        passwordError: null,
        passwordSuccess: null,
      });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('feedback', {
        user: req.user,
        error: errors.array()[0].msg,
        success: null,
        passwordError: null,
        passwordSuccess: null,
      });
    }

    try {
      await Feedback.create({
        userId: req.user.id,
        message: req.body.message,
        fileUuid: req.fileUuid || null,
        originalFilename: req.file?.originalname
          ? req.file.originalname.substring(0, 255)
          : null,
        fileMimeType: req.file?.mimetype || null,
        fileSizeBytes: req.file?.size || null,
      });

      logger.security('FEEDBACK_SUBMITTED', {
        userId: req.user.id,
        hasFile: !!req.file,
        fileUuid: req.fileUuid || null,
      });

      res.render('feedback', {
        user: req.user,
        error: null,
        success: 'Feedback submitted successfully.',
        passwordError: null,
        passwordSuccess: null,
      });

    } catch (err) {
      logger.error({ event: 'FEEDBACK_SAVE_ERROR', error: err.message });
      res.status(500).render('feedback', {
        user: req.user,
        error: 'Could not save feedback. Please try again.',
        success: null,
        passwordError: null,
        passwordSuccess: null,
      });
    }
  }
);

// ─── GET /moderator ───────────────────────────────────────────────────────────
router.get('/moderator', requireAuth, requireRole('moderator', 'admin'), async (req, res) => {
  try {
    const listings = await Listing.findAll({
      where: { status: 'pending' },
      include: [{ model: User, attributes: ['username'] }],
      order: [['createdAt', 'ASC']],
    });
    res.render('moderator', { user: req.user, listings, error: null });
  } catch (err) {
    logger.error({ event: 'MODERATOR_LOAD_ERROR', error: err.message });
    res.status(500).render('error', { message: 'Could not load moderator panel.', status: 500 });
  }
});

// ─── GET /moderator/download/:uuid ────────────────────────────────────────────
router.get('/moderator/download/:uuid',
  requireAuth,
  requireRole('moderator', 'admin'),
  async (req, res) => {
    try {
      const { uuid } = req.params;

      const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      if (!UUID_REGEX.test(uuid)) {
        return res.status(400).render('error', { message: 'Invalid file identifier.', status: 400 });
      }

      const feedback = await Feedback.findOne({ where: { fileUuid: uuid } });
      if (!feedback) {
        return res.status(404).render('error', { message: 'File not found.', status: 404 });
      }

      const uploadDir = process.env.UPLOAD_DIR || 'uploads';
      const uploadPath = path.join(process.cwd(), uploadDir);

      const files = fs.readdirSync(uploadPath);
      const match = files.find(f => f.startsWith(uuid));

      if (!match) {
        return res.status(404).render('error', { message: 'File not found on disk.', status: 404 });
      }

      const filePath = path.join(uploadPath, match);

      logger.security('MODERATOR_FILE_DOWNLOAD', {
        moderatorId: req.user.id,
        fileUuid: uuid,
        feedbackId: feedback.id,
      });

      res.download(filePath, feedback.originalFilename || match);

    } catch (err) {
      logger.error({ event: 'MODERATOR_DOWNLOAD_ERROR', error: err.message });
      res.status(500).render('error', { message: 'Could not download file.', status: 500 });
    }
  }
);

module.exports = router;