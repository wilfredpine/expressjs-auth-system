const express = require('express');
const router = express.Router();

const { authenticateTokenAndRedirect } = require('../middlewares/jwt_verifier');
const { index } = require('../controllers/homeController');

router.get('/', authenticateTokenAndRedirect, index);

module.exports = router;
