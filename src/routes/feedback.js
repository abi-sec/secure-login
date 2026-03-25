'use strict';

const express = require('express');
const { body, validationResult } = require('express-validator');
const Feedback = require('../models/Feedback');
const logger = require('../utils/logger');
const { requireAuth } = require('../middleware/rbac');
const { uploadLimiter } = require('../middleware/rateLimiter');
const { upload, validateFileSignature } = require('../middleware/fileValidator');

const router = express.Router();

// ─── GET /feedback ────────────────────────────────────────────────────────────
router.get('/feedback', requireAuth, (req, res) => {
  res.render('feedback', { user: req.user, error: null, success: null });
});

// ─── POST /feedback ───────────────────────────────────────────────────────────
router.post('/feedback',
  requireAuth,
  uploadLimiter,

  // Handle multipart form with optional file upload
  // multer runs first — enforces file size limit and declared MIME type
  (req, res, next) => {
    upload.single('attachment')(req, res, (err) => {
      if (err) {
        // Multer errors: file too large, wrong type, etc.
        logger.security('UPLOAD_MULTER_ERROR', {
          userId: req.user?.id,
          error: err.message,
        });
        return res.status(400).render('feedback', {
          user: req.user,
          error: err.message,
          success: null,
        });
      }
      next();
    });
  },

  // Hex signature validation — runs after multer saves the file
  validateFileSignature,

  // Input validation for the feedback message
  [
    body('message')
      .trim()
      // Whitelist: allow letters, numbers, spaces, common punctuation
      // This strips anything that looks like a script tag or SQL operator
      .matches(/^[a-zA-Z0-9 .,!?'\-\n\r@#()]+$/)
      .withMessage('Message contains invalid characters.')
      .isLength({ min: 1, max: 2000 })
      .withMessage('Message must be between 1 and 2000 characters.')
      .escape(), // HTML-encode remaining special chars — defence-in-depth against XSS
  ],

  async (req, res) => {
    // Check for upload signature rejection from middleware
    if (req.uploadError) {
      return res.status(400).render('feedback', {
        user: req.user,
        error: req.uploadError,
        success: null,
      });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('feedback', {
        user: req.user,
        error: errors.array()[0].msg,
        success: null,
      });
    }

    try {
      await Feedback.create({
        userId: req.user.id,
        message: req.body.message,
        fileUuid: req.fileUuid || null,
        // Store original filename for display only — NEVER used in file paths
        originalFilename: req.file?.originalname
          ? req.file.originalname.substring(0, 255)  // truncate to column limit
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
      });

    } catch (err) {
      logger.error({ event: 'FEEDBACK_SAVE_ERROR', error: err.message });
      res.status(500).render('feedback', {
        user: req.user,
        error: 'Could not save feedback. Please try again.',
        success: null,
      });
    }
  }
);

module.exports = router;
