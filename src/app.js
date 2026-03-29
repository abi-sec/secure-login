'use strict';

process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT:', err.message, err.stack);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION:', reason);
  process.exit(1);
});

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const passport = require('./config/passport');
const path = require('path');
const fs = require('fs');
const logger = require('./utils/logger');
const { connectDB, sequelize } = require('./config/database');
const { generalLimiter } = require('./middleware/rateLimiter');

// ─── Model associations ───────────────────────────────────────────────────────
const User = require('./models/User');
const Feedback = require('./models/Feedback');
User.hasMany(Feedback, { foreignKey: 'userId' });
Feedback.belongsTo(User, { foreignKey: 'userId' });

// ─── Ensure required directories exist ───────────────────────────────────────
const uploadDir = process.env.UPLOAD_DIR || 'uploads';
const logsDir = 'logs';
[uploadDir, logsDir].forEach(dir => {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Trust proxy ──────────────────────────────────────────────────────────────
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// ─── View engine ─────────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── Helmet — secure HTTP headers ────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
    },
  },
  noSniff: true,
  hidePoweredBy: true,
  hsts: process.env.NODE_ENV === 'production'
    ? { maxAge: 31536000, includeSubDomains: true }
    : false,
}));

// ─── General rate limiter ─────────────────────────────────────────────────────
app.use(generalLimiter);

// ─── Body parsers ─────────────────────────────────────────────────────────────
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));

// ─── Session ──────────────────────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sid',
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 2 * 60 * 60 * 1000,
  },
}));

// ─── Passport ─────────────────────────────────────────────────────────────────
app.use(passport.initialize());
app.use(passport.session());

// ─── Static files ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../public')));

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use('/', require('./routes/auth'));
app.use('/', require('./routes/feedback'));
app.use('/', require('./routes/admin'));

// Root redirect
app.get('/', (req, res) => {
  res.redirect(req.isAuthenticated() ? '/feedback' : '/login');
});

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).render('error', { message: 'Page not found.', status: 404 });
});

// ─── Global error handler ─────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  logger.error({ event: 'UNHANDLED_ERROR', error: err.message, stack: err.stack });
  const message = process.env.NODE_ENV === 'production'
    ? 'An internal error occurred.'
    : err.message;
  res.status(500).render('error', { message, status: 500 });
});

// ─── Startup ──────────────────────────────────────────────────────────────────
(async () => {
  await connectDB();
  await sequelize.authenticate();
  logger.info({ event: 'DB_SYNCED' });

  app.listen(PORT, () => {
    logger.info({ event: 'APP_STARTED', port: PORT, env: process.env.NODE_ENV });
    console.log(`✅ Server running on http://localhost:${PORT}`);
  });
})();

module.exports = app;