const { createLogger, format, transports } = require('winston');
const PostgresTransport = require('./winston-postgres-transport');

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
