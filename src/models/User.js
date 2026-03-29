'use strict';

const { DataTypes } = require('sequelize');
const argon2 = require('argon2');
const crypto = require('crypto');
const { sequelize } = require('../config/database');
const logger = require('../utils/logger');

// ─── Encryption helpers (AES-256-GCM) ───────────────────────────────────────
// AES-256-GCM is authenticated encryption — it guarantees both
// confidentiality AND integrity. If the ciphertext is tampered with,
// decryption will throw, which is exactly what we want.

const ALGORITHM = 'aes-256-gcm';
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // 32 bytes

function encrypt(plaintext) {
  if (!plaintext) return null;
  const iv = crypto.randomBytes(12); // 96-bit IV — recommended for GCM
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag(); // GCM authentication tag (16 bytes)
  // Store as: iv:authTag:ciphertext (all hex-encoded)
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

function decrypt(stored) {
  if (!stored) return null;
  const [ivHex, authTagHex, encryptedHex] = stored.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
  decipher.setAuthTag(authTag);
  return decipher.update(encrypted) + decipher.final('utf8');
}

// ─── Model ───────────────────────────────────────────────────────────────────

const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },

  username: {
    type: DataTypes.STRING(64),
    allowNull: false,
    unique: true,
    validate: {
      // Whitelist: only alphanumeric + underscore
      is: /^[a-zA-Z0-9_]+$/,
      len: [3, 64],
    },
  },

  // Email is stored encrypted at rest (AES-256-GCM)
  // If the DB is leaked, email addresses remain unreadable
  emailEncrypted: {
    type: DataTypes.TEXT,
    allowNull: true,
    field: 'email_encrypted',
  },

  // Argon2 hash — never store plaintext or bcrypt here
  passwordHash: {
    type: DataTypes.TEXT,
    allowNull: false,
    field: 'password_hash',
  },

  role: {
    type: DataTypes.ENUM('user', 'admin'),
    defaultValue: 'user',
    allowNull: false,
  },

  // Track failed login attempts for account lockout
  failedLoginAttempts: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    field: 'failed_login_attempts',
  },

  lockedUntil: {
    type: DataTypes.DATE,
    allowNull: true,
    field: 'locked_until',
  },
}, {
  tableName: 'users',
  timestamps: true,
  underscored: true,
});

// ─── Instance methods ─────────────────────────────────────────────────────────

/**
 * Hash a password using Argon2id.
 * Argon2id is memory-hard — significantly more resistant to
 * GPU-based cracking than bcrypt or SHA-256.
 */
User.hashPassword = async function (plaintext) {
  return argon2.hash(plaintext, {
    type: argon2.argon2id,
    memoryCost: 65536,  // 64 MB — makes GPU attacks expensive
    timeCost: 3,        // 3 iterations
    parallelism: 4,
  });
};

User.prototype.verifyPassword = async function (plaintext) {
  return argon2.verify(this.passwordHash, plaintext);
};

User.prototype.isLocked = function () {
  return this.lockedUntil && new Date() < new Date(this.lockedUntil);
};

User.prototype.setEmail = function (email) {
  this.emailEncrypted = encrypt(email);
};

User.prototype.getEmail = function () {
  try {
    return decrypt(this.emailEncrypted);
  } catch {
    // Decryption failure = tampered ciphertext — log and return null
    logger.security('EMAIL_DECRYPT_FAILURE', { userId: this.id });
    return null;
  }
};

User.associate = (models) => {
  User.hasMany(models.Feedback, { foreignKey: 'userId' });
};

module.exports = User;
