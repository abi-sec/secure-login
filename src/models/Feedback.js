'use strict';

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Feedback = sequelize.define('Feedback', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },

  userId: {
    type: DataTypes.UUID,
    allowNull: false,
    field: 'user_id',
    references: { model: 'users', key: 'id' },
  },

  // Sanitized feedback text  (express-validator strips dangerous chars upstream)
  message: {
    type: DataTypes.TEXT,
    allowNull: false,
    validate: { len: [1, 2000] },
  },

  // File upload metadata
  // Original filename is stored separately for display only (never used in paths)
  fileUuid: {
    type: DataTypes.UUID,
    allowNull: true,
    field: 'file_uuid',
  },

  //Original filename for display
  // stored only for UI display
  originalFilename: {
    type: DataTypes.STRING(255),
    allowNull: true,
    field: 'original_filename',
  },

  fileMimeType: {
    type: DataTypes.STRING(64),
    allowNull: true,
    field: 'file_mime_type',
  },

  fileSizeBytes: {
    type: DataTypes.INTEGER,
    allowNull: true,
    field: 'file_size_bytes',
  },

}, {
  tableName: 'feedback',
  timestamps: true,
  underscored: true,
});

Feedback.associate = (models) => {
  Feedback.belongsTo(models.User, { foreignKey: 'userId' });
};

module.exports = Feedback;
