const csrfTokens = require('./csrf-tokens');

/**
 * CSRF Middleware
 * Ensures protection against CSRF attacks.
 * @param {Object} [options] - Configuration options.
 * @param {Function} [options.value] - Function to extract the token from the request.
 * @param {Object} [options.cookie] - Cookie configuration.
 * @param {number} [options.secretLength=18] - Length of the generated secret.
 * @param {number} [options.hashRounds=10] - Number of bcrypt hashing rounds.
 * @returns {Function} Middleware function.
 */
module.exports = function csrfMiddleware(options = {}) {
  const { value: getTokenFromRequest = extractToken, cookie: cookieOptions = {} } = options;
  const cookieKey = cookieOptions.key || '_csrf';
  const isSigned = cookieOptions.signed || false;
  const tokenUtils = csrfTokens(options);

  return async (req, res, next) => {
    try {
      let secret = getSecret(req, cookieKey, isSigned);

      if (!secret) {
        secret = await tokenUtils.generateSecret();
        storeSecret(res, secret, cookieKey, cookieOptions);
      }

      req.csrfToken = async () => tokenUtils.createToken(secret);

      if (isSafeMethod(req.method)) return next();

      const userToken = getTokenFromRequest(req);
      if (!userToken || !(await tokenUtils.verifyToken(secret, userToken))) {
        throw createCsrfError('Invalid or missing CSRF token', 'EBADCSRFTOKEN', 403);
      }

      next();
    } catch (err) {
      next(err);
    }
  };
};

/**
 * Checks if the HTTP method is safe (does not modify server state).
 * @param {string} method - HTTP method.
 * @returns {boolean} True if safe, otherwise false.
 */
function isSafeMethod(method) {
  return ['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase());
}

/**
 * Extracts the CSRF token from the request.
 * @param {Object} req - The request object.
 * @returns {string|undefined} The token value.
 */
function extractToken(req) {
  return req.body?._csrf || req.query?._csrf || req.headers['x-csrf-token'] || req.headers['x-xsrf-token'];
}

/**
 * Retrieves the CSRF secret from cookies.
 * @param {Object} req - The request object.
 * @param {string} key - Cookie key to retrieve the secret.
 * @param {boolean} isSigned - Whether the cookie is signed.
 * @returns {string|undefined} The retrieved secret.
 */
function getSecret(req, key, isSigned) {
  return isSigned ? req.signedCookies?.[key] : req.cookies?.[key];
}

/**
 * Stores the CSRF secret in cookies.
 * @param {Object} res - The response object.
 * @param {string} secret - The secret to store.
 * @param {string} key - Cookie key to store the secret under.
 * @param {Object} options - Cookie configuration.
 */
function storeSecret(res, secret, key, options) {
  res.cookie(key, secret, options);
}

/**
 * Creates an error for CSRF issues.
 * @param {string} message - Error message.
 * @param {string} code - Error code.
 * @param {number} status - HTTP status code.
 * @returns {Error} The generated error.
 */
function createCsrfError(message, code, status) {
  const error = new Error(message);
  error.code = code;
  error.status = status;
  return error;
}
