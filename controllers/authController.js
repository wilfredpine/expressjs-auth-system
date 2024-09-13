const db = require('../models/db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Secret key used to sign the JWT
const JWT_SECRET = process.env.JWT_SECRET;

const showLoginForm = (req, res) => {
    res.render('login');
};

const showRegisterForm = (req, res) => {
    res.render('register');
};

const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Find the user by email
        const users = await db.users.findOne({ where: { email } });

        // Validate user existence and password
        if (!users || !bcrypt.compareSync(password, users.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Create a JWT payload
        const tokenPayload = { id: users.id, email: users.email, role: users.role };

        // Generate JWT
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1h' });

        // Set JWT in an HTTP-only, secure cookie
        res.cookie('authToken', token, {
            httpOnly: process.env.cookie_httpOnly,   // Cannot be accessed by JavaScript
            secure: process.env.cookie_secure,    // Set to true if you're using HTTPS
            sameSite: process.env.cookie_sameSite // 'strict' = Helps prevent CSRF, 'lax' is less restrictive and should work with most requests
        });

        // redirect to home page
        return res.redirect('/home');

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

const logout = (req, res) => {
    res.clearCookie('authToken'); // Clear the JWT cookie
    //res.json({ message: 'Logged out' });
    return res.redirect('/auth/login');
};

const register = async (req, res) => {
    const { name, email, password } = req.body;

    try {

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const users = await db.users.create({ name, email, password: hashedPassword });

        // Render login page after successful registration
        //res.render('login', { message: 'Registration successful, please log in.' });
        return res.redirect('/auth/login');

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

module.exports = {
    showLoginForm,
    showRegisterForm,
    login,
    logout,
    register
};