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

const { authenticateTokenAdmin } = require('../middlewares/jwt_verifier');


router.get('/', authenticateTokenAdmin, (req, res) => {
    user = req.user
    res.send(`Welcome admin {user}`);
});

module.exports = router;
