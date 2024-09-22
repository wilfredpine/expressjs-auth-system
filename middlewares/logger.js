/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

const { createLogger, format, transports } = require('winston');
const PostgresTransport = require('./winston-postgres-transport');

/**
 * Logger
 */
const logger = createLogger({
    level: 'info',
    format: format.combine(
        format.timestamp(),
        format.json()
    ),
    transports: [
        new PostgresTransport()
        // Add other transports if needed
    ]
});

module.exports = logger;
