'use strict';

const logger = require('../utils/logger');

/**
 * Require an authenticated session.
 * Redirects to login if the user is not authenticated.
 */
function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  logger.security('UNAUTHENTICATED_ACCESS', { path: req.path, ip: req.ip });
  res.redirect('/login');
}

/**
 * Require a specific role.
 * Usage: requireRole('admin')
 *
 * Logs privilege escalation attempts — a user trying to access
 * an admin route is a significant security event.
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res.redirect('/login');
    }

    if (roles.includes(req.user.role)) {
      return next();
    }

    // Log the privilege escalation attempt
    logger.security('PRIVILEGE_ESCALATION_ATTEMPT', {
      userId: req.user.id,
      username: req.user.username,
      userRole: req.user.role,
      requiredRoles: roles,
      path: req.path,
      ip: req.ip,
    });

    res.status(403).render('error', {
      message: 'Access denied.',
      status: 403,
    });
  };
}

module.exports = { requireAuth, requireRole };
