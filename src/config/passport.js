'use strict';

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/User');
const logger = require('../utils/logger');

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

passport.use(new LocalStrategy(
  { usernameField: 'username', passwordField: 'password' },
  async (username, password, done) => {
    try {
      // Find user (sequelize ORM has paramaterized queries built-in so no SQL injection)
      const user = await User.findOne({ where: { username } });

      //User not found
      //Return the same generic error as wrong password.
      //Different messages for "user not found" vs "wrong password" enable
      //username enumeration attacks.
      if (!user) {
        logger.security('LOGIN_FAILURE_USER_NOT_FOUND', { username });
        return done(null, false, { message: 'Invalid credentials.' });
      }

      //Account locked
      if (user.isLocked()) {
        logger.security('LOGIN_FAILURE_ACCOUNT_LOCKED', {
          username,
          lockedUntil: user.lockedUntil,
        });
        return done(null, false, { message: 'Account temporarily locked. Try again later.' });
      }

      //Password check
      const valid = await user.verifyPassword(password);

      if (!valid) {
        //Increment failed attempts
        user.failedLoginAttempts += 1;

        //Lock the account if threshold exceeded
        if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
          user.lockedUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
          logger.security('ACCOUNT_LOCKED', {
            username,
            attempts: user.failedLoginAttempts,
            lockedUntil: user.lockedUntil,
          });
        } else {
          logger.security('LOGIN_FAILURE_BAD_PASSWORD', {
            username,
            attempts: user.failedLoginAttempts,
          });
        }

        await user.save();
        return done(null, false, { message: 'Invalid credentials.' });
      }

      //Success
      //Reset failed attempts on successful login
      if (user.failedLoginAttempts > 0) {
        user.failedLoginAttempts = 0;
        user.lockedUntil = null;
        await user.save();
      }

      logger.security('LOGIN_SUCCESS', { username, userId: user.id, role: user.role });
      return done(null, user);

    } catch (err) {
      logger.error({ event: 'LOGIN_ERROR', error: err.message });
      return done(err);
    }
  }
));

//Serialize only the user ID into the session cookie
passport.serializeUser((user, done) => {
  done(null, user.id);
});

//Deserialize: look up the user by ID on every request
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findByPk(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

module.exports = passport;
