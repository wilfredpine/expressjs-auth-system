/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

const index = (req, res) => {
    user = req.user
    res.render('index', user);
};


module.exports = {
    index,
};