/**
 * Authentication System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

require('@dotenvx/dotenvx').config()

const JWT_SECRET =      process.env.JWT_SECRET;                      // Secret key used to sign the JWT

const db =              require('../models/db');
const jwt =             require('jsonwebtoken');

/**
 * Admin user verification
 * Middleware to verify JWT and handle redirection
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @returns 
 */
const authenticateTokenAdmin = async (req, res, next) => {
    
    const token =           req.session.authToken;                  // Extract token from session
    const currentRoute =    req.originalUrl || req.path;            // Get the current route being accessed
    
    // Log token and current route for debugging
    //console.log('Token from session:', token);
    //console.log('Current route:', currentRoute);

    /** If no token is provided, redirect to login page */
    if (!token) {

        if (currentRoute !== '/auth/login') {
            return res.redirect('/auth/login');                     //console.log('No token found, redirecting to /auth/login');
        } else {
            return next();                                          // If already on the login page, proceed
        }

    }

    try {

        const decoded = jwt.verify(token, JWT_SECRET);              // Verify token
        
        const user = await db.users.findByPk(decoded.id);           // Find user by ID from the decoded token

        if (!user) {
            //console.log('User not found, clearing session and redirecting to /auth/login');
            req.session = null;                                     // Clear session
            return res.redirect('/auth/login');
        }

        // If token is valid, save the decoded payload to request object
        req.user = user;                                            // Store user object in request
        req.token = token;                                          // Store token in request

        // Redirect based on user role only if not on the correct route
        if (user.role === 'admin') {
            return next();
        } else {
            // If role is unknown or missing, clear session and redirect to login page
            req.session = null;                                     // Clear session
            if (currentRoute !== '/auth/login') {
                //console.log('Unknown role, clearing session and redirecting to /auth/login');
                return res.redirect('/auth/login');
            } else {
                // If already on the login page, proceed
                return next();
            }
        }

        // If everything is fine, proceed to the next middleware
        return next();

    } catch (err) {
        //console.error('Token verification error:', err);
        // If token is invalid or expired, clear session and redirect to login page
        req.session = null; // Clear session
        if (currentRoute !== '/auth/login') {
            //console.log('Token verification failed, clearing session and redirecting to /auth/login');
            return res.redirect('/auth/login');
        } else {
            // If already on the login page, proceed
            return next();
        }
    }
};


/**
 * User userrole verification
 * Middleware to verify JWT and handle redirection
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @returns 
 */
const authenticateTokenUser = async (req, res, next) => {

    // Extract token from session
    const token = req.session.authToken;

    // Get the current route being accessed
    const currentRoute = req.originalUrl || req.path;
    
    // If no token is provided, redirect to login page
    if (!token) {
        if (currentRoute !== '/auth/login') {
            //console.log('No token found, redirecting to /auth/login');
            return res.redirect('/auth/login');
        } else {
            // If already on the login page, proceed
            return next();
        }
    }

    try {
        // Verify token
        const decoded = jwt.verify(token, JWT_SECRET);
        //console.log('Decoded token:', decoded);

        // Find user by ID from the decoded token
        const user = await db.users.findByPk(decoded.id);
        if (!user) {
            //console.log('User not found, clearing session and redirecting to /auth/login');
            req.session = null; // Clear session
            return res.redirect('/auth/login');
        }

        // If token is valid, save the decoded payload to request object
        req.user = user; // Store user object in request
        req.token = token; // Store token in request

        // Redirect based on user role only if not on the correct route
        if (user.role === 'user') {
            return next();
        } else {
            // If role is unknown or missing, clear session and redirect to login page
            req.session = null; // Clear session
            if (currentRoute !== '/auth/login') {
                //console.log('Unknown role, clearing session and redirecting to /auth/login');
                return res.redirect('/auth/login');
            } else {
                // If already on the login page, proceed
                return next();
            }
        }

        // If everything is fine, proceed to the next middleware
        return next();

    } catch (err) {
        //console.error('Token verification error:', err);
        // If token is invalid or expired, clear session and redirect to login page
        req.session = null; // Clear session
        if (currentRoute !== '/auth/login') {
            //console.log('Token verification failed, clearing session and redirecting to /auth/login');
            return res.redirect('/auth/login');
        } else {
            // If already on the login page, proceed
            return next();
        }
    }
};

module.exports = { authenticateTokenAdmin, authenticateTokenUser };