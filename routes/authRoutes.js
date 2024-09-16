const express = require('express');
const router = express.Router();
const { showLoginForm, showRegisterForm, login, logout, register } = require('../controllers/authController');
const { body, validationResult } = require('express-validator');

// Validation rules
const registrationValidators = [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email address'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
];
const loginValidators = [
    body('email').isEmail().withMessage('Invalid email address')
];

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

router.get('/logout', logout);

module.exports = router;
