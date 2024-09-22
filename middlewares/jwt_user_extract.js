/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

require('dotenv').config();

const jwt = require('jsonwebtoken');

const SECRET_KEY = process.env.JWT_SECRET;              // Ensure this matches the secret used to sign your tokens


/**
 * Extract user information from Token
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @returns 
 */
function extractUserFromToken(req, res, next) {
    const token = req.session.authToken;                // Check if the token exists in the session
    if (!token) {
        return next();                                  // No token found, proceed without user information
    }
    try {
        const decoded = jwt.verify(token, SECRET_KEY);  // Decode and verify the token
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
