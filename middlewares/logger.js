/**
 * Authentication System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

const { createLogger, format, transports } = require('winston');

/**
 * Logger
 */
const logger = createLogger({
    level: 'info',
    format: format.combine(
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        format.printf(({ timestamp, level, message, meta }) => {
            const metaInfo = meta
                ? ` | meta: ${JSON.stringify(meta)}`
                : '';
            return `${timestamp} | ${level.toUpperCase()} | ${message}${metaInfo}`;
        })
    ),
    transports: [
        new transports.File({
            filename: 'logs/app.log', // Save logs to this file
            level: 'info', // Minimum log level
            maxsize: 5242880, // Max size of log file (5MB)
            maxFiles: 5, // Rotate after 5 files
            tailable: true, // Keep the most recent logs in rotation
        })
    ]
});

module.exports = logger;
