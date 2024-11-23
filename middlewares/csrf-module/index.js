const csrfTokens = require('./csrf-tokens');
const csrfMiddleware = require('./csrf-middleware');

/**
 * Index file for CSRF module.
 * Exports the CSRF middleware for enforcing token validation.
 */
module.exports = {
  csrfTokens,
  csrfMiddleware, // Middleware for CSRF protection
};
