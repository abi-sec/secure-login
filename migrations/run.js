'use strict';

/**
 * Migration runner.
 * Reads all .sql files in this directory in order and executes them
 * against the configured PostgreSQL database.
 *
 * Usage: npm run migrate
 */

require('dotenv').config();
const { Client } = require('pg');
const fs = require('fs');
const path = require('path');

async function runMigrations() {
  const client = new Client({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 5432,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
  });

  try {
    await client.connect();
    console.log('✅ Connected to PostgreSQL');

    const migrationDir = __dirname;
    const sqlFiles = fs
      .readdirSync(migrationDir)
      .filter(f => f.endsWith('.sql'))
      .sort(); // Runs in filename order: 001_, 002_, etc.

    for (const file of sqlFiles) {
      const filePath = path.join(migrationDir, file);
      const sql = fs.readFileSync(filePath, 'utf8');
      console.log(`▶  Running migration: ${file}`);
      await client.query(sql);
      console.log(`   ✅ Done: ${file}`);
    }

    console.log('\n✅ All migrations completed successfully.');

  } catch (err) {
    console.error('❌ Migration failed:', err.message);
    process.exit(1);
  } finally {
    await client.end();
  }
}

runMigrations();
