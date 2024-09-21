/**
 * Authenticaton System
 * Using ExpressJS
 * By: Wilfred V. Pine
 * https://github.com/wilfredpine/
 * https://github.com/wilfredpine/expressjs-auth
 * @8/2024
 */

module.exports = (sequelize, DataTypes) => {
    const users = sequelize.define('users', {
      name: {
        type: DataTypes.STRING,
        allowNull: false
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: {
          isEmail: true,
        }
      },
      password: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      isVerified: {
          type: DataTypes.BOOLEAN,
          defaultValue: false,
      },
      resetToken: {
          type: DataTypes.STRING,
          allowNull: true,
      },
      resetTokenExpiry: {
          type: DataTypes.DATE,
          allowNull: true,
      },
      role: {
        type: DataTypes.STRING,
        allowNull: false,
        defaultValue: 'user'
      }

    }, {
      tableName: 'users' // Explicitly specify table name if different
    });

    return users;
  };
  