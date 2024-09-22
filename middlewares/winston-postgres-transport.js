/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

const Transport = require('winston-transport');
const util = require('util');

const db = require('../models/db');

/**
 * Winston PostgresTransport - used to saved the logs
 */
class PostgresTransport extends Transport {
    constructor(options) {
        super(options);
        // Consume any custom options here. e.g.:
        // - Connection information for databases
        // - Authentication information for APIs (e.g. loggly, papertrail,
        //   logentries, etc.).
    }

    async log(info, callback) {
        const { level, message, meta = {} } = info;
        try {
            await db.logs.create({
                level,
                message,
                meta: {
                    method: meta.method,
                    url: meta.url,
                    ip: meta.ip,
                    headers: meta.headers,
                    user: {
                        id: meta.user ? meta.user.id : 'unknown',
                        username: meta.user ? meta.user.username : 'anonymous',
                        email: meta.user ? meta.user.email : 'anonymous'
                    },
                    userAgent: meta.userAgent,
                    referer: meta.referer,
                },
                timestamp: new Date()
            });
        } catch (error) {
            console.error('Failed to write log to PostgreSQL', error);
        }
        callback();
    }
}

module.exports = PostgresTransport;
