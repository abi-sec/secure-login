'use strict';

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Listing = sequelize.define('Listing', {
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

  title: {
    type: DataTypes.STRING(128),
    allowNull: false,
    validate: { len: [3, 128] },
  },

  address: {
    type: DataTypes.STRING(255),
    allowNull: false,
    validate: { len: [5, 255] },
  },

  price: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false,
    validate: { min: 0 },
  },

  description: {
    type: DataTypes.TEXT,
    allowNull: true,
  },

  // Stored as comma-separated UUIDs e.g. "uuid1,uuid2,uuid3"
  imageUuids: {
    type: DataTypes.TEXT,
    allowNull: true,
    field: 'image_uuids',
  },

  status: {
    type: DataTypes.ENUM('pending', 'approved', 'rejected'),
    defaultValue: 'pending',
    allowNull: false,
  },

}, {
  tableName: 'listings',
  timestamps: true,
  underscored: true,
});

// Helper to get image UUIDs as array
Listing.prototype.getImageUuidsArray = function () {
  if (!this.imageUuids) return [];
  return this.imageUuids.split(',').filter(Boolean);
};

module.exports = Listing;