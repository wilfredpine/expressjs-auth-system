/**
 * Attendance Monitoring System
 * Using ExpressJS
 */
require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');

// const cookieParser = require('cookie-parser');
const cookieSession = require('cookie-session');

const app = express(); // express app
const port = process.env.PORT || 3000; // port

/**
 * Template engine
 */
app.set('view engine', 'ejs');

// Listen for request
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

/**
 * Middleware & Static files
 * Set path for static files (e.g., CSS, images)
 */ 
app.use(express.static(path.join(__dirname, 'public')));
//app.use(express.static(path.join(__dirname, 'uploads')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(bodyParser.urlencoded({ extended: false })); // Parse application/x-www-form-urlencoded
app.use(bodyParser.json()); // Parse application/json

// app.use(cookieParser());  // Middleware to parse cookies
// Configure cookie-session middleware
app.use(cookieSession({
    name: 'session',
    secret: process.env.COOKIE_SESSION_SECRET || 'default-secret', // Replace with a strong secret
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }));

/**
 * Models
 */
const db = require('./models/db');

db.sequelize.sync({ force: false }).then(() => {
    console.log('Database & tables created!');
  }); //Using { force: true } will drop the tables if they already exist. You can remove this option or set it to false in a production environment to prevent data loss.

/**
 * Routes
 */
const homeRoutes = require('./routes/homeRoutes');
const authRoutes = require('./routes/authRoutes');

app.use('/home', homeRoutes);
app.use('/', homeRoutes);
app.use('/auth', authRoutes);

/**
 * 404 Page
 */ 
app.use((req, res) => {
    res.status(404).render('404',  { 'title': '404'});
});
