/**
 * Attendance Monitoring System
 * Using ExpressJS
 */
require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');

const cookieParser = require('cookie-parser');
const cookieSession = require('cookie-session');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const helmet = require('helmet');

const session = require('express-session');
const flash = require('connect-flash');

const app = express(); // express app

const HOST = process.env.HOST || 'localhost';
const port = process.env.PORT || 3000; // port
const NODE_ENV = process.env.NODE_ENV || 'development';

/**
 * Template engine
 */
app.set('view engine', 'ejs');

// Listen for request
app.listen(port, HOST, () => {
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

app.use(cookieParser(process.env.COOKIE_PARSER_SECRET_KEY));  // Middleware to parse cookies

// Configure cookie-session middleware
app.use(cookieSession({
    name: process.env.COOKIE_SESSION_NAME,
    secret: process.env.COOKIE_SESSION_SECRET || 'default-secret', // Replace with a strong secret
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    cookie: {
      httpOnly: process.env.COOKIE_SESSION_HTTPONLY, // Prevent client-side JavaScript from accessing the cookie
      secure: NODE_ENV === 'production', // Only use `secure` in production
      sameSite: process.env.COOKIE_SESSION_SAMESITE // Helps prevent CSRF attacks
    }
  }));

// Rate Limiter (Prevents brute-force attacks by limiting the number of requests from a single IP address.)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    message: 'Too many requests from this IP, please try again later.'
  })
//app.use('/api/', limiter); // specific route
app.use(limiter); // all route

// CSRF
app.use(csrf({ 
    cookie: {
      httpOnly: process.env.COOKIE_SESSION_HTTPONLY, // Prevent client-side JavaScript from accessing the cookie
      secure: NODE_ENV === 'production', // Only use `secure` in production
      sameSite: process.env.COOKIE_SESSION_SAMESITE // Helps prevent CSRF attacks
    } 
  }));
// Middleware to make CSRF token available in response locals
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

app.use(helmet());

// Use express-session for another part of your application
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: true
}));

app.use(flash());

// Add a middleware to make flash messages available in response locals
app.use((req, res, next) => {
  res.locals.errors = req.flash('errors');
  res.locals.formData = req.flash('formData')[0] || {};
  next();
});

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


// Error handling middleware for CSRF errors
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
      res.status(403).send('Form has expired or tampered with.');
  } else {
      next(err);
  }
});

/**
 * 404 Page
 */ 
app.use((req, res) => {
    res.status(404).render('404',  { 'title': '404'});
});

