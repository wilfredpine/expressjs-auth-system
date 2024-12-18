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

const { authenticateTokenUser } = require('../middlewares/jwt_verifier');
const { index } = require('../controllers/homeController');

router.get('/', authenticateTokenUser, index);

module.exports = router;
