'use strict';

const express = require('express');
const { body, validationResult } = require('express-validator');
const Listing = require('../models/Listing');
const User = require('../models/User');
const logger = require('../utils/logger');
const { requireAuth, requireRole } = require('../middleware/rbac');
const { uploadMultiple, validateMultipleFileSignatures } = require('../middleware/fileValidator');
const path = require('path');
const fs = require('fs');

const router = express.Router();

router.get('/home', requireAuth, async (req, res) => {
  try {
    const listings = await Listing.findAll({
      where: { status: 'approved' },
      include: [{ model: User, attributes: ['username'] }],
      order: [['createdAt', 'DESC']],
    });
    res.render('home', { user: req.user, listings, error: null });
  } catch (err) {
    logger.error({ event: 'HOME_LOAD_ERROR', error: err.message });
    res.status(500).render('error', { message: 'Could not load listings.', status: 500 });
  }
});

router.get('/listings/new', requireAuth, (req, res) => {
  res.render('listing', { user: req.user, error: null, success: null });
});

router.post('/listings/new',
  requireAuth,

  (req, res, next) => {
    uploadMultiple.array('images', 5)(req, res, (err) => {
      if (err) {
        logger.security('UPLOAD_MULTER_ERROR', {
          userId: req.user?.id,
          error: err.message,
        });
        return res.status(400).render('listing', {
          user: req.user,
          error: err.message,
          success: null,
        });
      }
      next();
    });
  },

  validateMultipleFileSignatures,

  [
    body('title')
      .trim()
      .matches(/^[a-zA-Z0-9 .,!?'\-#&()]+$/).withMessage('Title contains invalid characters.')
      .isLength({ min: 3, max: 128 }).withMessage('Title must be 3–128 characters.'),
    body('address')
      .trim()
      .matches(/^[a-zA-Z0-9 .,#'-]+$/).withMessage('Address contains invalid characters.')
      .isLength({ min: 5, max: 255 }).withMessage('Address must be 5–255 characters.'),
    body('price')
      .isFloat({ min: 0 }).withMessage('Price must be a positive number.'),
    body('description')
      .optional()
      .trim()
      .matches(/^[a-zA-Z0-9 .,!?'\-\n\r@#()]+$/).withMessage('Description contains invalid characters.')
      .isLength({ max: 2000 }).withMessage('Description must be under 2000 characters.')
      .escape(),
  ],

  async (req, res) => {
    if (req.uploadError) {
      return res.status(400).render('listing', {
        user: req.user,
        error: req.uploadError,
        success: null,
      });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('listing', {
        user: req.user,
        error: errors.array()[0].msg,
        success: null,
      });
    }

    try {
      const imageUuids = (req.fileUuids || []).join(',');

      await Listing.create({
        userId: req.user.id,
        title: req.body.title,
        address: req.body.address,
        price: parseFloat(req.body.price),
        description: req.body.description || null,
        imageUuids: imageUuids || null,
        status: 'pending',
      });

      logger.security('LISTING_SUBMITTED', {
        userId: req.user.id,
        imageCount: req.fileUuids?.length || 0,
      });

      res.render('listing', {
        user: req.user,
        error: null,
        success: 'Listing submitted successfully. It will appear once approved by a moderator.',
      });

    } catch (err) {
      logger.error({ event: 'LISTING_SAVE_ERROR', error: err.message });
      res.status(500).render('listing', {
        user: req.user,
        error: 'Could not save listing. Please try again.',
        success: null,
      });
    }
  }
);

router.get('/listings/image/:uuid',
  requireAuth,
  async (req, res) => {
    try {
      const { uuid } = req.params;

      const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      if (!UUID_REGEX.test(uuid)) {
        return res.status(400).render('error', { message: 'Invalid image identifier.', status: 400 });
      }

      const uploadPath = path.join(process.cwd(), process.env.UPLOAD_DIR || 'uploads');
      const files = fs.readdirSync(uploadPath);
      const match = files.find(f => f.startsWith(uuid));

      if (!match) {
        return res.status(404).render('error', { message: 'Image not found.', status: 404 });
      }

      res.sendFile(path.join(uploadPath, match));

    } catch (err) {
      logger.error({ event: 'IMAGE_SERVE_ERROR', error: err.message });
      res.status(500).render('error', { message: 'Could not load image.', status: 500 });
    }
  }
);

router.post('/listings/:id/approve',
  requireAuth,
  requireRole('moderator', 'admin'),
  async (req, res) => {
    try {
      const listing = await Listing.findByPk(req.params.id);
      if (!listing) return res.status(404).render('error', { message: 'Listing not found.', status: 404 });

      listing.status = 'approved';
      await listing.save();

      logger.security('LISTING_APPROVED', {
        moderatorId: req.user.id,
        listingId: listing.id,
      });

      res.redirect('/moderator');
    } catch (err) {
      logger.error({ event: 'LISTING_APPROVE_ERROR', error: err.message });
      res.status(500).render('error', { message: 'Could not approve listing.', status: 500 });
    }
  }
);

router.post('/listings/:id/reject',
  requireAuth,
  requireRole('moderator', 'admin'),
  async (req, res) => {
    try {
      const listing = await Listing.findByPk(req.params.id);
      if (!listing) return res.status(404).render('error', { message: 'Listing not found.', status: 404 });

      listing.status = 'rejected';
      await listing.save();

      logger.security('LISTING_REJECTED', {
        moderatorId: req.user.id,
        listingId: listing.id,
      });

      res.redirect('/moderator');
    } catch (err) {
      logger.error({ event: 'LISTING_REJECT_ERROR', error: err.message });
      res.status(500).render('error', { message: 'Could not reject listing.', status: 500 });
    }
  }
);

module.exports = router;