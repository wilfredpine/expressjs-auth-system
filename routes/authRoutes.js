const express = require('express');
const router = express.Router();
const { showLoginForm, showRegisterForm, login, logout, register } = require('../controllers/authController');

router.get('/login', showLoginForm);
router.post('/login', login);
router.get('/register', showRegisterForm);
router.post('/register', register);
router.get('/logout', logout);

module.exports = router;
