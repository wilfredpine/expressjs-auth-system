const crypto = require('crypto');

module.exports = csrfTokens;

function csrfTokens(options) {
  options = options || {};

  const secretLength = options.secretLength || 18;
  const saltLength = options.saltLength || 8;
  const tokenize = options.tokenize || csrfTokens.tokenize;

  return {
    secret(cb) {
      const secret = crypto.randomBytes(secretLength).toString('base64');
      cb(null, secret); // Call the callback with the secret
    },

    secretSync() {
      return crypto.randomBytes(secretLength).toString('base64');
    },

    create(secret) {
      const salt = crypto.randomBytes(saltLength).toString('base64');
      return tokenize(secret, salt);
    },

    verify(secret, token) {
      if (!token || typeof token !== 'string') return false;
      const [salt] = token.split('-');
      const expectedToken = tokenize(secret, salt);
      return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken));
    },
  };
}

csrfTokens.tokenize = function tokenize(secret, salt) {
  const hash = crypto.createHash('sha1')
    .update(salt)
    .update('-')
    .update(secret)
    .digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); // URL-safe base64
  return `${salt}-${hash}`;
};
