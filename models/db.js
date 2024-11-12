/**
 * Authentication System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

require('dotenv').config();
const logger = require('../middlewares/logger');
const path = require('path');
const { Sequelize } = require('sequelize');

/**
 * Database Connection
 * Passing parameters separately (other dialects)
 */

    const sequelize = new Sequelize({
        dialect:    'sqlite',
        storage:    path.join(__dirname, 'database.sqlite'),    // Path to SQLite file
        logging:    false                                       // Disable query logging (optional)
    });

    if(process.env.DB_DIALECT !== 'sqlite'){

        sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
            host:       process.env.DB_HOST,
            dialect:    process.env.DB_DIALECT,
            port:       process.env.DB_PORT,                    // Default PostgreSQL port
            logging:    false,                                  // Disable query logging (optional)
            pool: {
                max:        5,                                  // Max connections
                min:        0,
                acquire:    30000,                              // Max time to get a connection
                idle:       10000                               // Max time a connection can be idle
            }
        });

    }

    (async () => {
        try {
            await sequelize.authenticate();

            logger.info('Connection has been established successfully.');
            console.log('Connection has been established successfully.');

        } catch (error) {

            logger.error('Unable to connect to the database');
            console.error('Unable to connect to the database:', error);

        }
    })();
    

const db = {};
db.Sequelize = Sequelize;
db.sequelize = sequelize;

/**
 * Require Models Here
 */
db.users = require('./users')(sequelize, Sequelize);    // users Model

module.exports = db;





/**
 * Sample Model with Relationships
 */
// ---Models---
// db.Student = require('./student')(sequelize, Sequelize);
// db.Activity = require('./activity')(sequelize, Sequelize);
// db.Attendance = require('./attendance')(sequelize, Sequelize);
// ---Relationships---
// db.Student.hasMany(db.Attendance, { foreignKey: 'StudentId' });
// db.Activity.hasMany(db.Attendance, { foreignKey: 'ActivityId' });
// db.Attendance.belongsTo(db.Student, { foreignKey: 'StudentId' });
// db.Attendance.belongsTo(db.Activity, { foreignKey: 'ActivityId' });
