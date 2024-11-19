/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */


/**
 * Load node modules
 */

  /** .env */
  require('@dotenvx/dotenvx').config()

  const express =     require('express')
  const bodyParser =  require('body-parser');
  const path =        require('path');

  /**
   * express-session
   * 
   * Manages user sessions by storing session data on the server side.
   * Only a session ID is stored in the browser (cookie), the session data itself is secure on the server side
   */
  const session =     require('express-session');

  /** crypto - random generator */
  const crypto =      require('crypto');

  /**
   * cookie-parser
   * 
   * reads cookies from the Cookie header in incoming HTTP requests and makes them available in req.cookies
   * it doesn’t create sessions or store data on the server. Instead, it just parses the cookies into an accessible format.
   * Often used alongside express-session or cookie-session to read additional cookies.
   * Useful when you need to read or modify cookies in requests but don’t require full session management
   */
  const cookieParser =        require('cookie-parser');

  /**
   * cookie-session
   * 
   * lightweight middleware that stores session data in a cookie rather than on the server.
   * the entire session object is serialized and sent to the client in a signed cookie, making it accessible across requests.
   * Stores session data in a client-side cookie (up to around 4KB, due to cookie size limits)
   * Signed cookies are used to ensure data integrity, but sensitive data should be avoided in client-side cookies
   * Since the session is stored on the client, cookie-session is useful for stateless applications
   * Ideal for lightweight sessions with limited data, where server-side storage is unnecessary, or for scaling applications that don't require complex session storage
   */
  const cookieSession =       require('cookie-session');

  /**
   * My Custom CSRF Module
   * - CSRF Protection
   */
  const { csrfMiddleware } =  require('./middlewares/csrf-module'); // Import csrfMiddleware from your module

  /**
   * Rate Limiter
   * - for brute force protection
   */
  const rateLimit =           require('express-rate-limit');

  /**
   * Helmet
   * - Content Security Policy (CSP)
   */
  const helmet =              require('helmet');

  /**
   * Connect-flash
   * - used for Flash Alert
   */
  const flash =               require('connect-flash');

  /**
   * Logger
   */
  const logger =              require('./middlewares/logger');

/**
 * Define apps info
 */

  const app =                 express();
  const host =                process.env.HOST || 'localhost';
  const port =                process.env.PORT || 3000; 
  const environment =         process.env.NODE_ENV || 'development';
  const upload_directory =    process.env.UPLOAD_DIR || '/uploads';

/**
 * Start the Application
 * Listen for request
 */

  app.listen(port, host, () => {

    if (environment === 'development') {

      console.log(`[DEBUG] Server started on port ${port}`);
      logger.warn(`[DEBUG] Server is running on port ${port}`);

    } else if (environment === 'secure') {

      console.log(`Server started on port ${port}`);
      logger.info(`Server is running on port ${port}`);

    }

  });

/**
 * Template engine
 */
  app.set('view engine', 'ejs');


/**
 * Static files / Public Directory
 * Set path for static files (e.g., CSS, images)
 * Filter Files (e.g. Blocked Executable files)
 */ 
  app.use(express.static(path.join(__dirname, 'public'), {

    setHeaders: (res, path) => {
      if (path.endsWith('.exe') || path.endsWith('.bat') || path.endsWith('.EXE') || path.endsWith('.BAT')) {
        return res.status(403).send('Executable files are forbidden.');
      }
    }

  }));
  /** Also block access to .json files */
  app.use((req, res, next) => {

    if (req.url.endsWith('.json') || req.url.endsWith('.JSON')) {
      return res.status(403).send('Access to JSON files is forbidden.');
    }
    next();

  });


/**
 * Upload Directory
 * Set the directory for Uploaded Files
 * - blocked specific files
 */
  const forbiddenExtensions = ['.exe', '.bat','.EXE', '.BAT'];

  /** Middleware to block access based on multiple conditions */
  app.use(upload_directory, (req, res, next) => {

    const fileExtension = path.extname(req.path);

    if (forbiddenExtensions.includes(fileExtension)) {
      return res.status(403).send('Access to this file is forbidden.');
    }
    next();

  });

  /** 
   * app.use(express.static(path.join(__dirname, upload_directory)));  
   * http://<your-domain>/image.jpg
   * app.use('/uploads', express.static(path.join(__dirname, upload_directory)));
   * http://<your-domain>/uploads/image.jpg
   */
  app.use('/uploads', express.static(path.join(__dirname, upload_directory)));


/**
 * Body Parser
 * Middleware to parse JSON and URL-encoded data
 */
  app.use(bodyParser.urlencoded({ extended: true }));                   // Parse application/x-www-form-urlencoded
  app.use(bodyParser.json());                                           // Parse application/json

/**
 * Middleware to parse cookies
 * 
 * cookie-parser
 * cookie-session
 */

  app.use(
    cookieParser(process.env.COOKIE_PARSER_SECRET_KEY)
  );

  app.use(cookieSession({
    name:         process.env.COOKIE_SESSION_NAME,
    secret:       process.env.COOKIE_SESSION_SECRET || 'default-secret',  // Replace with a strong secret
    maxAge:       24 * 60 * 60 * 1000,                                    // 24 hours
    cookie: {
      httpOnly:   process.env.COOKIE_SESSION_HTTPONLY,                    // Prevent client-side JavaScript from accessing the cookie
      secure:     environment === 'production',                           // Only use `secure` in production
      sameSite:   process.env.COOKIE_SESSION_SAMESITE                     // Helps prevent CSRF attacks
    }
  }));


/**
 * Rate Limiter middleware
 * Rate Limiter (Prevents brute-force attacks by limiting the number of requests from a single IP address.)
 */
  const limiter = rateLimit({
    windowMs:         15 * 60 * 1000,                                      // 15 minutes
    limit:            100,                                                 // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    standardHeaders:  true,                                                // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders:    false,                                               // Disable the `X-RateLimit-*` headers
    message:          'Too many requests from this IP, please try again later.'
  })

  /** app.use('/api/', limiter); */                                        // specific route
  app.use(limiter);                                                        // all routes


/**
 * CSRF using Custom Middleware
 */
  app.use(csrfMiddleware({ 
    cookie: { 
      key:            '_csrf', 
      httpOnly:       process.env.COOKIE_SESSION_HTTPONLY,
      secure:         environment === 'production', 
      sameSite:       process.env.COOKIE_SESSION_SAMESITE 
    }
  }));

  /** Middleware to make CSRF token available in response locals */
  app.use((req, res, next) => {

    res.locals.csrfToken = req.csrfToken();
    next();

  });


/**
 * Helmet middleware
 * - Content Security Policy (CSP)
 */

  /**const cspConfig = {
    directives: {
        defaultSrc: ["'self'"],
        // scriptSrc: ["'self'", "https://cdn.tailwindcss.com"],  // Allow Tailwind CSS CDN
        // styleSrc: ["'self'", "https://cdn.tailwindcss.com"],   // Allow inline styles from CDN
        // Add other directives as needed
    },
  };**/

  /** Apply helmet middleware */
  app.use(helmet());
  /** Apply helmet middleware with custom CSP */
  /** app.use(helmet.contentSecurityPolicy(cspConfig)); */


/**
 * Session middleware
 * Use `express-session` for another part of your application
 */
  app.use(session({
    secret:             process.env.SESSION_SECRET || 'your-session-secret',
    resave:             process.env.SESSION_RESAVE,
    saveUninitialized:  process.env.SESSION_SAVEUNINITIALIZED,
    cookie: { 
      httpOnly:         process.env.SESSION_HTTPONLY, 
      secure:           process.env.SESSION_SECURE,
      sameSite:         process.env.SESSION_SAMESITE  
    } 
  }));


/**
 * use `Alert`
 * Add a middleware to make flash messages available in response locals
 * - $ errors
 * - $ formData
 */
  app.use(flash());

  app.use((req, res, next) => {

    res.locals.errors =   req.flash('errors');
    res.locals.formData = req.flash('formData')[0] || {};
    next();

  });


/**
 * Logger
 */
  const extractUserFromToken = require('./middlewares/jwt_extract_user');
  app.use(extractUserFromToken);                                    // Use the middleware to extract user information

  /** Middleware to log request details */
  const get_client_ip =         require('./middlewares/get_client_ip');

  app.use((req, res, next) => {

    const start =               Date.now();
    const clientIp =            get_client_ip(req);
    
    logger.info('Request received', {                               // Log request details
        method:                 req.method,
        url:                    req.url,
        ip:                     clientIp,
        headers:                req.headers,
        user: {
            id:         req.user ? req.user.id : 'unknown',
            username:   req.user ? req.user.username : 'anonymous',
            email:      req.user ? req.user.email : 'anonymous'
        },
        meta: {
            userAgent:  req.headers['user-agent'],
            referer:    req.headers.referer,
            method:     req.method,
            url:        req.url,
            ip:         clientIp,
            headers:    req.headers,
            user: {
              id:       req.user ? req.user.id : 'unknown',
              username: req.user ? req.user.username : 'anonymous',
              email:    req.user ? req.user.email : 'anonymous'
            }
        }
    });

    /** Capture response status and duration */
    res.on('finish', () => {

        const duration =    Date.now() - start;
        logger.info('Request completed', {
            method:         req.method,
            url:            req.url,
            status:         res.statusCode,
            duration:       `${duration}ms`
        });

    });

    next();

  });



/**
 * Models
 * 
 */
  const db = require('./models/db');
  db.sequelize.sync({ 
    force: false                            // Using { force: true } will drop the tables if they already exist. You can remove this option or set it to false in a production environment to prevent data loss.
  }).then(() => {                           // load | sync database
    console.log('Database & tables created!');
  });



/**
 * Routes
 */
  const homeRoutes = require('./routes/homeRoutes');
  const authRoutes = require('./routes/authRoutes');

  app.use('/home', homeRoutes);
  app.use('/', homeRoutes);
  app.use('/auth', authRoutes);



/**
 * Error handling middleware for CSRF and Other errors
 */
  app.use((err, req, res, next) => {

    if (err.code === 'EBADCSRFTOKEN') { /** Handle CSRF errors */

      logger.warn('CSRF error', { message: err.message, stack: err.stack });
      res.status(403).send('Form has expired or tampered with.');

    } else {

      // next(err);
      /** Handle other errors */
      logger.error('Unhandled error', { message: err.message, stack: err.stack });
      res.status(500).send('Internal Server Error');

    }

  });


/**
 * 404 Page
 */ 
  app.use((req, res) => {

    logger.error('404 error');
    res.status(404).render('404',  { 'title': '404'});

  });

