require('dotenv').config();
// Secret key used to sign the JWT
const JWT_SECRET = process.env.JWT_SECRET;

const db = require('../models/db');
const jwt = require('jsonwebtoken');

// Middleware to verify JWT
const authenticateTokenAndRedirect = async (req, res, next) => {

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