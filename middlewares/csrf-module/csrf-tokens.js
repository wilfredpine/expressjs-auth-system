const bcrypt = require('bcryptjs');

module.exports = csrfTokens;

function csrfTokens(options) {
  options = options || {};

  const secretLength = options.secretLength || 18;
  const saltRounds = options.saltRounds || 10;
  const tokenize = options.tokenize || csrfTokens.tokenize;

  return {
    secret(cb) {
      const secret = generateRandomString(secretLength);
      cb(null, secret); // Call the callback with the secret
    },

    secretSync() {
      return generateRandomString(secretLength);
    },

    async create(secret) {
      const salt = generateRandomString(8); // Generate a simple salt
      const hash = await tokenize(secret, salt);
      return `${salt}-${hash}`;
    },

    async verify(secret, token) {
      if (!token || typeof token !== 'string') return false;
      const [salt, hash] = token.split('-');
      if (!salt || !hash) return false;

      const expectedHash = await tokenize(secret, salt);
      return bcrypt.compare(expectedHash, hash);
    },
  };
}

csrfTokens.tokenize = async function tokenize(secret, salt) {
  const rawToken = `${salt}-${secret}`;
  return bcrypt.hash(rawToken, 10); // Hash with bcrypt
};

function generateRandomString(length) {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return result;
}
