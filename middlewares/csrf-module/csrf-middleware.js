const csrfTokens = require('./csrf-tokens');  // Import your updated csrf-tokens.js file

const ignoreMethod = {
    GET: true,
    HEAD: true,
    OPTIONS: true,
};

module.exports = function csrf(options) {
    options = options || {};
    const value = options.value || defaultValue;
    const cookie = options.cookie;
    const cookieKey = (cookie && cookie.key) || '_csrf';
    const signedCookie = cookie && cookie.signed;

    const tokens = csrfTokens(options);  // Initialize tokens using csrfTokens function

    if (cookie && typeof cookie !== 'object') cookie = {};

    return function(req, res, next) {
        // Retrieve existing secret if it exists
        let secret;
        if (cookie) {
            secret = (
                (signedCookie && req.signedCookies && req.signedCookies[cookieKey]) ||
                (!signedCookie && req.cookies && req.cookies[cookieKey])
            );
        } else if (req.session) {
            secret = req.session.csrfSecret;
        } else {
            const err = new Error('misconfigured csrf');
            err.status = 500;
            next(err);
            return;
        }
        if (secret) return createToken(secret);

        // Generate new secret if none exists
        tokens.secret(function(err, secret) {
            if (err) return next(err);
            if (cookie) {
                res.cookie(cookieKey, secret, cookie);
            } else if (req.session) {
                req.session.csrfSecret = secret;
            } else {
                const err = new Error('misconfigured csrf');
                err.status = 500;
                next(err);
                return;
            }
            createToken(secret);
        });

        // Generate the token
        function createToken(secret) {
            // Lazy-load token
            let token;
            req.csrfToken = function csrfToken() {
                return token || (token = tokens.create(secret));
            };

            // Ignore specified methods
            if (ignoreMethod[req.method]) return next();

            // Verify user-submitted token value
            if (!tokens.verify(secret, value(req))) {
                const err = new Error('invalid csrf token');
                err.status = 403;
                next(err);
                return;
            }

            next();
        }
    };
};

/**
 * Default value function, checking the `req.body`
 * and `req.query` for the CSRF token.
 *
 * @param {IncomingMessage} req
 * @return {String}
 * @api private
 */

function defaultValue(req) {
    return (req.body && req.body._csrf) ||
           (req.query && req.query._csrf) ||
           (req.headers['x-csrf-token']) ||
           (req.headers['x-xsrf-token']);
}
