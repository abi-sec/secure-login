'use strict';

const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');

// Only images allowed
const ALLOWED_TYPES = {
  'image/jpeg': { ext: '.jpg' },
  'image/png':  { ext: '.png' },
  'image/gif':  { ext: '.gif' },
  'image/webp': { ext: '.webp' },
};

const MAX_SIZE_BYTES = (parseInt(process.env.MAX_FILE_SIZE_MB, 10) || 5) * 1024 * 1024;
const UPLOAD_DIR = process.env.UPLOAD_DIR || 'uploads';

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const fileUuid = uuidv4();
    cb(null, `${fileUuid}.tmp`);
  },
});

const multerFilter = (req, file, cb) => {
  if (ALLOWED_TYPES[file.mimetype]) {
    cb(null, true);
  } else {
    logger.security('UPLOAD_REJECTED_MIME', {
      userId: req.user?.id,
      declaredMime: file.mimetype,
      originalName: file.originalname,
    });
    cb(new Error(`File type not allowed. Only JPEG, PNG, GIF and WEBP images are accepted.`), false);
  }
};

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_SIZE_BYTES,
    files: 1,
    fields: 10,
    headerPairs: 2000,
  },
  fileFilter: multerFilter,
});

async function validateFileSignature(req, res, next) {
  if (!req.file) return next();

  const fs = require('fs');

  try {
    const { fileTypeFromFile } = await import('file-type');
    const detected = await fileTypeFromFile(req.file.path);

    const declaredMime = req.file.mimetype;

    // All allowed types (images) have magic bytes so undefined is always invalid
    if (!detected) {
      throw new Error('Could not determine file type from binary signature');
    }

    if (detected.mime !== declaredMime) {
      throw new Error(
        `Signature mismatch: declared=${declaredMime}, actual=${detected.mime}`
      );
    }

    const ext = ALLOWED_TYPES[declaredMime]?.ext || '.bin';
    const finalPath = req.file.path.replace('.tmp', ext);
    fs.renameSync(req.file.path, finalPath);

    const fileUuid = path.basename(req.file.filename, '.tmp');
    req.fileUuid = fileUuid;
    req.fileFinalPath = finalPath;

    logger.security('UPLOAD_ACCEPTED', {
      userId: req.user?.id,
      fileUuid,
      mime: declaredMime,
      sizeBytes: req.file.size,
    });

    next();

  } catch (err) {
    try {
      require('fs').unlinkSync(req.file.path);
    } catch {
      // intentionally ignored
    }

    logger.security('UPLOAD_REJECTED_SIGNATURE', {
      userId: req.user?.id,
      reason: err.message,
      declaredMime: req.file.mimetype,
      originalName: req.file.originalname,
    });

    req.uploadError = 'File rejected: only JPEG, PNG, GIF and WEBP images are accepted.';
    next();
  }
}

module.exports = { upload, validateFileSignature, ALLOWED_TYPES };