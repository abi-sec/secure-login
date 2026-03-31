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

const User = require('./models/User');
const Feedback = require('./models/Feedback');
const Listing = require('./models/Listing');
const AuditLog = require('./models/AuditLog');

User.hasMany(Feedback, { foreignKey: 'userId' });
Feedback.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Listing, { foreignKey: 'userId' });
Listing.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(AuditLog, { foreignKey: 'userId' });
AuditLog.belongsTo(User, { foreignKey: 'userId' });

const uploadDir = process.env.UPLOAD_DIR || 'uploads';
const logsDir = 'logs';
[uploadDir, logsDir].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

const app = express();
const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

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

app.use(generalLimiter);

app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));

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

app.use(passport.initialize());
app.use(passport.session());

app.use(express.static(path.join(__dirname, '../public')));

app.use('/', require('./routes/auth'));
app.use('/', require('./routes/feedback'));
app.use('/', require('./routes/admin'));
app.use('/', require('./routes/listings'));

app.get('/', (req, res) => {
  res.redirect(req.isAuthenticated() ? '/home' : '/login');
});

app.use((req, res) => {
  res.status(404).render('error', { message: 'Page not found.', status: 404 });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  logger.error({ event: 'UNHANDLED_ERROR', error: err.message, stack: err.stack });
  const message = process.env.NODE_ENV === 'production'
    ? 'An internal error occurred.'
    : err.message;
  res.status(500).render('error', { message, status: 500 });
});

(async () => {
  await connectDB();
  await sequelize.authenticate();
  logger.info({ event: 'DB_SYNCED' });

  app.listen(PORT, () => {
    logger.info({ event: 'APP_STARTED', port: PORT, env: process.env.NODE_ENV });
    console.log(` Server running on http://localhost:${PORT}`);
  });
})();

module.exports = app;