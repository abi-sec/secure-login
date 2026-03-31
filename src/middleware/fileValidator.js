'use strict';

const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');

const ALLOWED_TYPES = {
  'image/jpeg': { ext: '.jpg' },
  'image/png':  { ext: '.png' },
  'image/gif':  { ext: '.gif' },
  'image/webp': { ext: '.webp' },
};

const MAX_SIZE_BYTES = (parseInt(process.env.MAX_FILE_SIZE_MB, 10) || 5) * 1024 * 1024;
const UPLOAD_DIR = process.env.UPLOAD_DIR || 'uploads';
const MAX_FILES = 5;

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
    cb(new Error('File type not allowed. Only JPEG, PNG, GIF and WEBP images are accepted.'), false);
  }
};

// Single file upload (kept for any future single-upload use)
const uploadSingle = multer({
  storage,
  limits: {
    fileSize: MAX_SIZE_BYTES,
    files: 1,
    fields: 10,
    headerPairs: 2000,
  },
  fileFilter: multerFilter,
});

// Multiple images upload (max 5 for listings)
const uploadMultiple = multer({
  storage,
  limits: {
    fileSize: MAX_SIZE_BYTES,
    files: MAX_FILES,
    fields: 20,
    headerPairs: 2000,
  },
  fileFilter: multerFilter,
});

// Validate hex signature for a single file
async function validateSingleFile(file) {
  const fs = require('fs');
  const { fileTypeFromFile } = await import('file-type');
  const detected = await fileTypeFromFile(file.path);
  const declaredMime = file.mimetype;

  if (!detected) {
    throw new Error('Could not determine file type from binary signature');
  }
  if (detected.mime !== declaredMime) {
    throw new Error(`Signature mismatch: declared=${declaredMime}, actual=${detected.mime}`);
  }

  const ext = ALLOWED_TYPES[declaredMime]?.ext || '.bin';
  const finalPath = file.path.replace('.tmp', ext);
  fs.renameSync(file.path, finalPath);

  const fileUuid = path.basename(file.filename, '.tmp');
  return { fileUuid, finalPath };
}

// Middleware: validate single file signature (feedback route)
async function validateFileSignature(req, res, next) {
  if (!req.file) return next();

  try {
    const { fileUuid, finalPath } = await validateSingleFile(req.file);
    req.fileUuid = fileUuid;
    req.fileFinalPath = finalPath;

    logger.security('UPLOAD_ACCEPTED', {
      userId: req.user?.id,
      fileUuid,
      mime: req.file.mimetype,
      sizeBytes: req.file.size,
    });

    next();
  } catch (err) {
    try { require('fs').unlinkSync(req.file.path); } catch { /* ignored */ }

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

// Middleware: validate multiple file signatures (listings route)
async function validateMultipleFileSignatures(req, res, next) {
  if (!req.files || req.files.length === 0) return next();
  const fs = require('fs');

  const validatedUuids = [];
  const errors = [];

  for (const file of req.files) {
    try {
      const { fileUuid } = await validateSingleFile(file);
      validatedUuids.push(fileUuid);

      logger.security('UPLOAD_ACCEPTED', {
        userId: req.user?.id,
        fileUuid,
        mime: file.mimetype,
        sizeBytes: file.size,
      });
    } catch (err) {
      try { fs.unlinkSync(file.path); } catch { /* ignored */ }

      logger.security('UPLOAD_REJECTED_SIGNATURE', {
        userId: req.user?.id,
        reason: err.message,
        declaredMime: file.mimetype,
        originalName: file.originalname,
      });

      errors.push(file.originalname);
    }
  }

  if (errors.length > 0) {
    // Clean up all validated files too since we reject the whole submission
    for (const uuid of validatedUuids) {
      const uploadPath = require('path').join(process.cwd(), UPLOAD_DIR);
      const allFiles = fs.readdirSync(uploadPath);
      const match = allFiles.find(f => f.startsWith(uuid));
      if (match) {
        try { fs.unlinkSync(require('path').join(uploadPath, match)); } catch { /* ignored */ }
      }
    }
    req.uploadError = `Some files were rejected. Only JPEG, PNG, GIF and WEBP images are accepted.`;
    return next();
  }

  req.fileUuids = validatedUuids;
  next();
}

module.exports = {
  upload: uploadSingle,
  uploadMultiple,
  validateFileSignature,
  validateMultipleFileSignatures,
  ALLOWED_TYPES,
};