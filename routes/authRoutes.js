/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

const express = require('express');
const router = express.Router();
const { showLoginForm, showRegisterForm, login, logout, register, verifyEmail, requestPasswordReset, renderResetPasswordForm, resetPassword } = require('../controllers/authController');
const { body, validationResult } = require('express-validator');

/**
 * Validation rules
 */
const registrationValidators = [
    body('name').notEmpty().trim().escape().withMessage('Name is required'),
    body('email').isEmail().normalizeEmail().withMessage('Invalid email address'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
];
const loginValidators = [
    body('email').isEmail().normalizeEmail().withMessage('Invalid email address')
];

/**
 * Login Route
 */
router.get('/login', showLoginForm);
router.post('/login', loginValidators,  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // Store validation errors and form data in flash
        req.flash('errors', errors.array());
        req.flash('formData', req.body);
        // Redirect back to the registration form
        return res.redirect('/auth/login');
    }
    next();
}, login);

/**
 * Registration Route
 */
router.get('/register', showRegisterForm);
// Apply validation middleware to the registration route
router.post('/register', registrationValidators, (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // Store validation errors and form data in flash
        req.flash('errors', errors.array());
        req.flash('formData', req.body);
        // Redirect back to the registration form
        return res.redirect('/auth/register');
    }
    next();
}, register);

/**
 * Logout Route
 */
router.get('/logout', logout);


/**
 * Email verification Route
 */
router.get('/verify-email', verifyEmail);

/**
 * Request password reset
 */
router.get('/reset-password', (req, res) => {
    res.render('reset-password', { errors: res.locals.errors });
});
router.post('/reset-password', requestPasswordReset);

/**
 * Password reset routes
 */
router.get('/new-password', renderResetPasswordForm);
router.post('/new-password',
    body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters long'),
    async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            return res.redirect('/auth/new-password');
        }
        next();
    },
    resetPassword
);

module.exports = router;
