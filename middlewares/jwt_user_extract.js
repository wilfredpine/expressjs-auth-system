require('dotenv').config();

const jwt = require('jsonwebtoken');

const SECRET_KEY = process.env.JWT_SECRET; // Ensure this matches the secret used to sign your tokens

function extractUserFromToken(req, res, next) {
    // Check if the token exists in the session
    const token = req.session.authToken;

    if (!token) {
        // No token found, proceed without user information
        return next();
    }

    try {
        // Decode and verify the token
        const decoded = jwt.verify(token, SECRET_KEY);

        // Attach user information to the request object
        req.user = {
            id: decoded.id,
            email: decoded.email,
            role: decoded.role
        };
    } catch (err) {
        console.error('Failed to authenticate token:', err);
        req.user = {}; // In case of error, set user to an empty object
    }

    // Proceed to the next middleware or route handler
    next();
}

module.exports = extractUserFromToken;
