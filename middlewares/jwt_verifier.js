require('dotenv').config();
// Secret key used to sign the JWT
const JWT_SECRET = process.env.JWT_SECRET;

const db = require('../models/db');
const jwt = require('jsonwebtoken');

// Middleware to verify JWT and handle redirection
const authenticateTokenAndRedirect = async (req, res, next) => {
    // Extract token from session
    const token = req.session.authToken;

    // Get the current route being accessed
    const currentRoute = req.originalUrl || req.path;
    
    // Log token and current route for debugging
    console.log('Token from session:', token);
    console.log('Current route:', currentRoute);

    // If no token is provided, redirect to login page
    if (!token) {
        if (currentRoute !== '/auth/login') {
            console.log('No token found, redirecting to /auth/login');
            return res.redirect('/auth/login');
        } else {
            // If already on the login page, proceed
            return next();
        }
    }

    try {
        // Verify token
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log('Decoded token:', decoded);

        // Find user by ID from the decoded token
        const user = await db.users.findByPk(decoded.id);
        if (!user) {
            console.log('User not found, clearing session and redirecting to /auth/login');
            req.session = null; // Clear session
            return res.redirect('/auth/login');
        }

        // If token is valid, save the decoded payload to request object
        req.user = user; // Store user object in request
        req.token = token; // Store token in request

        // Redirect based on user role only if not on the correct route
        if (user.role === 'user') {
            if (currentRoute !== '/home') {
                console.log('Redirecting user to /home');
                return res.redirect('/home');
            }
        } else if (user.role === 'admin') {
            if (currentRoute !== '/admin') {
                console.log('Redirecting admin to /admin');
                return res.redirect('/admin');
            }
        } else {
            // If role is unknown or missing, clear session and redirect to login page
            req.session = null; // Clear session
            if (currentRoute !== '/auth/login') {
                console.log('Unknown role, clearing session and redirecting to /auth/login');
                return res.redirect('/auth/login');
            } else {
                // If already on the login page, proceed
                return next();
            }
        }

        // If everything is fine, proceed to the next middleware
        return next();

    } catch (err) {
        console.error('Token verification error:', err);
        // If token is invalid or expired, clear session and redirect to login page
        req.session = null; // Clear session
        if (currentRoute !== '/auth/login') {
            console.log('Token verification failed, clearing session and redirecting to /auth/login');
            return res.redirect('/auth/login');
        } else {
            // If already on the login page, proceed
            return next();
        }
    }
};

// Middleware to verify JWT
const authenticateTokenAndRedirect_2 = async (req, res, next) => {

    const token = req.cookies.authToken; // Extract token from cookie
    
    // If no token is provided, redirect to login page
    if (!token) {
        return res.redirect('/auth/login');
    }

    // Verify token
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            // If token is invalid or expired, redirect to login page
            return res.redirect('/auth/login');
        }

        const users = db.users.findByPk(decoded.id);
        if (!users) return res.status(404).json({ error: "User not found" });

        // If token is valid, save the decoded payload to request object
        req.users = decoded;

        req.token = token; // Pass the token to the route

        if (req.users.role === 'user') {
            return res.redirect('/home');
        } else if (req.users.role === 'admin') {
            return res.redirect('/admin');
        } else {
            // If role is unknown or missing, redirect to login page
            return res.redirect('/auth/login');
        }

    });
};


module.exports = { authenticateTokenAndRedirect };