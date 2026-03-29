'use strict';

const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');

// Allowed file types and their expected MIME types
// These are checked against the hex signature
const ALLOWED_TYPES = {
  'image/jpeg': { ext: '.jpg' },
  'image/png':  { ext: '.png' },
  'application/pdf': { ext: '.pdf' },
  'text/plain': { ext: '.txt' },
};

const MAX_SIZE_BYTES = (parseInt(process.env.MAX_FILE_SIZE_MB, 10) || 5) * 1024 * 1024;
const UPLOAD_DIR = process.env.UPLOAD_DIR || 'uploads';

//Multer storage config
// Files are renamed to a random UUID immediately on disk.
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // UUID filename extension is determined by validated MIME type and not user input
    const fileUuid = uuidv4();
    // We'll append the correct extension after MIME validation
    // For now store with a .tmp extension, route handler renames after validation
    cb(null, `${fileUuid}.tmp`);
  },
});

// Multer filter
const multerFilter = (req, file, cb) => {
  if (ALLOWED_TYPES[file.mimetype]) {
    cb(null, true);
  } else {
    logger.security('UPLOAD_REJECTED_MIME', {
      userId: req.user?.id,
      declaredMime: file.mimetype,
      originalName: file.originalname,
    });
    cb(new Error(`File type not allowed: ${file.mimetype}`), false);
  }
};

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_SIZE_BYTES,
    files: 1,           //Only 1 file per request
    fields: 10,         //Max form fields
    headerPairs: 2000,  //Limit header parsing to prevent DoS
  },
  fileFilter: multerFilter,
});

//Post-upload hex signature validator
// Attackers rename .exe to .jpg to bypass extension checks.
// This function reads the actual binary header (magic bytes) of the file
// and verifies it matches the declared MIME type.

async function validateFileSignature(req, res, next) {
  if (!req.file) return next();

  const fs = require('fs');

  try {
    // Dynamic import cuz file-type is ESM only
    const { fileTypeFromFile } = await import('file-type');
    const detected = await fileTypeFromFile(req.file.path);

    const declaredMime = req.file.mimetype;

    // text/plain has no magic bytes so file-type returns undefined for it
    // We allow this only if the declared type is also text/plain
    if (!detected && declaredMime !== 'text/plain') {
      throw new Error('Could not determine file type from binary signature');
    }

    if (detected && detected.mime !== declaredMime) {
      throw new Error(
        `Signature mismatch: declared=${declaredMime}, actual=${detected.mime}`
      );
    }

    // Rename .tmp to correct extension
    
    const ext = ALLOWED_TYPES[declaredMime]?.ext || '.bin';
    const finalPath = req.file.path.replace('.tmp', ext);
    fs.renameSync(req.file.path, finalPath);

    // Extract UUID from filename
    const fileUuid = path.basename(req.file.filename, '.tmp');

    // Attach validated metadata to req for the route handler
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
    // Delete the rejected file immediately so no attacker files  on disk
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

    req.uploadError = 'File rejected: content does not match declared type.';
    next();
  }
}

module.exports = { upload, validateFileSignature, ALLOWED_TYPES };
