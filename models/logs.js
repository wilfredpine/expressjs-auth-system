/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

const { Sequelize } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
    const logs = sequelize.define('logs', {
        level: {
            type: DataTypes.STRING,
            allowNull: false
        },
        message: {
            type: DataTypes.TEXT,
            allowNull: false
        },
        meta: {
            type: DataTypes.JSONB
        },
        timestamp: {
            type: DataTypes.DATE,
            defaultValue: Sequelize.NOW
        }

    }, {
        timestamps: false,
        tableName: 'logs' // Explicitly specify table name if different
    });

    return logs;
  };
  