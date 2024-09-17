
const index = (req, res) => {
    user = req.user
    res.render('index', user);
};


module.exports = {
    index,
};