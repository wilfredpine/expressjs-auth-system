const bcrypt = require('bcryptjs');

/**
 * CSRF Token Utility
 * Provides methods to generate and validate CSRF tokens.
 * @param {Object} [options] - Configuration options.
 * @param {number} [options.secretLength=18] - Length of the generated secret.
 * @param {number} [options.hashRounds=10] - Number of bcrypt hashing rounds.
 * @returns {Object} Utility methods.
 */
module.exports = function csrfTokens({ secretLength = 18, hashRounds = 10 } = {}) {
  return {
    /**
     * Generates a random secret string.
     * @returns {Promise<string>} The generated secret.
     */
    async generateSecret() {
      return generateRandomString(secretLength);
    },

    /**
     * Creates a CSRF token using a secret.
     * @param {string} secret - The secret used to create the token.
     * @returns {Promise<string>} The generated token.
     */
    async createToken(secret) {
      const salt = generateRandomString(8);
      const hash = await bcrypt.hash(`${salt}-${secret}`, hashRounds);
      return `${salt}-${hash}`;
    },

    /**
     * Validates a CSRF token against a secret.
     * @param {string} secret - The original secret.
     * @param {string} token - The token to validate.
     * @returns {Promise<boolean>} True if the token is valid, otherwise false.
     */
    async verifyToken(secret, token) {
      if (!token) return false;
      const [salt, hash] = token.split('-');
      if (!salt || !hash) return false;
      return bcrypt.compare(`${salt}-${secret}`, hash);
    },
  };
};

/**
 * Generates a random alphanumeric string.
 * @param {number} length - Length of the string to generate.
 * @returns {string} The generated string.
 */
function generateRandomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({ length }, () => chars.charAt(Math.floor(Math.random() * chars.length))).join('');
}
