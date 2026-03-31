'use strict';

const { DataTypes } = require('sequelize');
const crypto = require('crypto');
const { sequelize } = require('../config/database');

const ALGORITHM = 'aes-256-gcm';
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // 32 bytes

function encrypt(plaintext) {
  if (!plaintext) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

const AuditLog = sequelize.define('AuditLog', {
  id: {
    type: DataTypes.BIGINT,
    autoIncrement: true,
    primaryKey: true,
  },

  event: {
    type: DataTypes.STRING(64),
    allowNull: false,
  },

  userId: {
    type: DataTypes.UUID,
    allowNull: true,
    field: 'user_id',
    references: { model: 'users', key: 'id' },
  },

  ipAddress: {
    type: DataTypes.STRING(45), // IP address length (INET mapped to string)
    allowNull: true,
    field: 'ip_address',
  },

  // Stored encrypted (AES-256-GCM)
  details: {
    type: DataTypes.TEXT,
    allowNull: true,
    set(value) {
      if (typeof value === 'object' && value !== null) {
        this.setDataValue('details', encrypt(JSON.stringify(value)));
      } else if (value) {
        this.setDataValue('details', encrypt(String(value)));
      } else {
        this.setDataValue('details', null);
      }
    }
  },

}, {
  tableName: 'audit_log',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: false, // The table only has created_at
  underscored: true,
});

AuditLog.associate = (models) => {
  AuditLog.belongsTo(models.User, { foreignKey: 'userId' });
};

module.exports = AuditLog;
