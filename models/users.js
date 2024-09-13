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
  