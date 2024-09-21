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

const { authenticateTokenAndRedirect } = require('../middlewares/jwt_verifier');
const { index } = require('../controllers/homeController');

router.get('/', authenticateTokenAndRedirect, index);

module.exports = router;
