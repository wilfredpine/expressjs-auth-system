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

const logger = require('./middlewares/logger');

const app = express(); // express app

const HOST = process.env.HOST || 'localhost';
const port = process.env.PORT || 3000; // port
const NODE_ENV = process.env.NODE_ENV || 'development';

// Set default log level or use the one from .env
const logLevel = process.env.LOG_LEVEL || 'info';

/**
 * Template engine
 */
app.set('view engine', 'ejs');

// Listen for request
app.listen(port, HOST, () => {
    if (logLevel === 'debug') {
      console.log(`[DEBUG] Server started on port ${port}`);
      logger.info(`[DEBUG] Server is running on port ${port}`);
    } else if (logLevel === 'info') {
      console.log(`Server started on port ${port}`);
      logger.info(`Server is running on port ${port}`);
    }
});

/**
 * Middleware & Static files
 * Set path for static files (e.g., CSS, images)
 */ 
app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, path) => {
      if (path.endsWith('.exe') || path.endsWith('.bat') || path.endsWith('.EXE') || path.endsWith('.BAT')) {
        return res.status(403).send('Executable files are forbidden.');
      }
    }
  }));

// Block access to .json files
app.use((req, res, next) => {
    if (req.url.endsWith('.json') || req.url.endsWith('.JSON')) {
      return res.status(403).send('Access to JSON files is forbidden.');
    }
    next();
  });

const forbiddenExtensions = ['.exe', '.bat','.EXE', '.BAT'];
// Middleware to block access based on multiple conditions
app.use('/uploads', (req, res, next) => {
    const fileExtension = path.extname(req.path);  // Get the file extension
    // Block specific files or extensions
    if (forbiddenExtensions.includes(fileExtension)) {
      return res.status(403).send('Access to this file is forbidden.');
    }
    next();
  });
  
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
 * Request Logging Middleware
 */
const extractUserFromToken = require('./middlewares/jwt_user_extract');
const get_client_ip = require('./middlewares/get_client_ip');

// Use the middleware to extract user information
app.use(extractUserFromToken);

// Middleware to log request details
app.use((req, res, next) => {
  const start = Date.now();
  const clientIp = get_client_ip(req);
  // Log request details
  logger.info('Request received', {
      method: req.method,
      url: req.url,
      ip: clientIp,
      headers: req.headers,
      user: {
          id: req.user ? req.user.id : 'unknown',
          username: req.user ? req.user.username : 'anonymous',
          email: req.user ? req.user.email : 'anonymous'
      },
      meta: {
          userAgent: req.headers['user-agent'],
          referer: req.headers.referer,
          method: req.method,
          url: req.url,
          ip: clientIp,
          headers: req.headers,
          user: {
            id: req.user ? req.user.id : 'unknown',
            username: req.user ? req.user.username : 'anonymous',
            email: req.user ? req.user.email : 'anonymous'
          }
      }
  });

  // Capture response status and duration
  res.on('finish', () => {
      const duration = Date.now() - start;
      logger.info('Request completed', {
          method: req.method,
          url: req.url,
          status: res.statusCode,
          duration: `${duration}ms`
      });
  });
  
  next();
});

/**
 * Routes
 */
const homeRoutes = require('./routes/homeRoutes');
const authRoutes = require('./routes/authRoutes');

app.use('/home', homeRoutes);
app.use('/', homeRoutes);
app.use('/auth', authRoutes);


// Error handling middleware for CSRF and Other errors
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
      // Handle CSRF errors
      logger.warn('CSRF error', { message: err.message, stack: err.stack });
      res.status(403).send('Form has expired or tampered with.');
  } else {
    // next(err);
      // Log the error and handle other errors
      logger.error('Unhandled error', { message: err.message, stack: err.stack });
      res.status(500).send('Internal Server Error');
  }
});

/**
 * 404 Page
 */ 
app.use((req, res) => {
    res.status(404).render('404',  { 'title': '404'});
});

