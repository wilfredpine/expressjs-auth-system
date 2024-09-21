/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

require('dotenv').config();

const db = require('../models/db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const { sendVerificationEmail, sendPasswordResetEmail } = require('../services/email_service');


// Secret key used to sign the JWT
const JWT_SECRET = process.env.JWT_SECRET;

const showLoginForm = (req, res) => {
    res.render('login', { errors: res.locals.errors, formData: res.locals.formData });
};

const showRegisterForm = (req, res) => {
    res.render('register', { errors: res.locals.errors, formData: res.locals.formData });
};

const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Find the user by email
        const users = await db.users.findOne({ where: { email } });

        // Validate user existence and password
        if (!users || !bcrypt.compareSync(password, users.password)) {
            //return res.status(401).json({ message: 'Invalid credentials' });
            req.flash('errors', [{ msg: 'Invalid credentials' }]);
            req.flash('formData', req.body);
            return res.redirect('/auth/login');
        }

        // Check if the user's email is verified
        if (!users.isVerified) {
            req.flash('errors', [{ msg: 'Please verify your email before logging in.' }]);
            req.flash('formData', req.body);
            return res.redirect('/auth/login');
        }

        // Create a JWT payload
        const tokenPayload = { id: users.id, email: users.email, role: users.role };

        // Generate JWT
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1h' });

        // Set JWT in an HTTP-only, secure cookie
        // res.cookie('authToken', token, {
        //     httpOnly: process.env.cookie_httpOnly,   // Cannot be accessed by JavaScript
        //     secure: process.env.cookie_secure,    // Set to true if you're using HTTPS
        //     sameSite: process.env.cookie_sameSite // 'strict' = Helps prevent CSRF, 'lax' is less restrictive and should work with most requests
        // });

         // Set JWT in session
         req.session.authToken = token;

        // redirect to home page
        return res.redirect('/home');

    } catch (error) {
        //console.error('Login error:', error);
        //res.status(500).json({ error: 'Internal server error' });
        req.flash('errors', [{ msg: 'Internal server error' }]);
        req.flash('formData', req.body);
        return res.redirect('/auth/login');
    }
};

const logout = (req, res) => {
    res.clearCookie('authToken'); // Clear the JWT cookie
    req.session = null; // Clear session data
    //res.json({ message: 'Logged out' });
    return res.redirect('/auth/login');
};

const register = async (req, res) => {
    const { name, email, password } = req.body;

    try {

        // Check if email already exists
        const existingUser = await db.users.findOne({ where: { email } });
        if (existingUser) {
            // If email already exists, send an error message
            req.flash('errors', [{ msg: 'Email already in use. Please choose a different email.' }]);
            req.flash('formData', req.body);
            return res.redirect('/auth/register');
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const users = await db.users.create({ name, email, password: hashedPassword });

        const tokenPayload = { id: users.id, email: users.email };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '24h' });

        // Sent email verification
        await sendVerificationEmail(email, token);

        req.flash('message', 'Registration successful. Please check your email to verify your account.');
        return res.redirect('/auth/login');

    } catch (error) {
        console.error('Registration error:', error);

        // Store general error message in flash
        req.flash('errors', [{ msg: 'Internal server error. Please try again later.' }]);
        req.flash('formData', req.body);

        // Redirect back to the registration form
        res.redirect('/auth/register');
    }
};

const verifyEmail = async (req, res) => {
    const { token } = req.query;

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await db.users.findOne({ where: { email: decoded.email } });

        if (!user) {
            return res.status(400).send('Invalid verification link');
        }

        user.isVerified = true;
        await user.save();

        return res.redirect('/auth/login');
    } catch (error) {
        console.error('Verification error:', error);
        return res.status(400).send('Invalid verification link');
    }
};

const requestPasswordReset = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await db.users.findOne({ where: { email } });
        if (!user) {
            req.flash('errors', [{ msg: 'No account found with that email address' }]);
            return res.redirect('/auth/reset-password');
        }

        const tokenPayload = { id: user.id, email: user.email };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1h' });

        await sendPasswordResetEmail(email, token);

        req.flash('message', 'Password reset link sent to your email');
        return res.redirect('/auth/login');
    } catch (error) {
        console.error('Password reset error:', error);
        req.flash('errors', [{ msg: 'Internal server error. Please try again later.' }]);
        return res.redirect('/auth/reset-password');
    }
};

// Controller for rendering the password reset form
const renderResetPasswordForm = (req, res) => {
    // Extract token from query params
    const token = req.query.token;

    // Check if token is provided
    if (!token) {
        req.flash('errors', [{ msg: 'Token is missing or invalid.' }]);
        return res.redirect('/auth/forgot-password'); // Redirect to a page where users can request a new password reset link
    }

    // Render the form with the token
    res.render('new-password', { errors: req.flash('errors'), token });
};

// Controller for handling the password reset
const resetPassword = async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await db.users.findByPk(decoded.id);

        if (!user) {
            req.flash('errors', [{ msg: 'Invalid or expired token' }]);
            return res.redirect('/auth/new-password');
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.isVerified = true;
        await user.save();

        req.flash('message', 'Password has been reset successfully');
        return res.redirect('/auth/login');
    } catch (error) {
        console.error('Password reset error:', error);
        req.flash('errors', [{ msg: 'An error occurred during password reset' }]);
        return res.redirect('/auth/new-password');
    }
};

module.exports = {
    showLoginForm,
    showRegisterForm,
    login,
    logout,
    register, 
    verifyEmail, 
    requestPasswordReset, 
    resetPassword,
    renderResetPasswordForm 
};