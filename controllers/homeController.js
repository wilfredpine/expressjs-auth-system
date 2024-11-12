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

const sample = (req, res) => {

    const { encode } = require('html-entities');
    const data = db.User.find();
    // Sanitize data
    const sanitizedData = data.map(data => {
        return {
            id: data.id,
            name: encode(data.name), // HTML-encode user name
            // Add more fields to sanitize as needed
            description: encode(data.description),
        };
    });
    res.render('sample',  { 'info': sanitizedData });

};

module.exports = {
    index,
};