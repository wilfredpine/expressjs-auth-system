module.exports = (sequelize, DataTypes) => {
    const Activity = sequelize.define('Activity', {
      date: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
        allowNull: false
      },
      activityName: {
        type: DataTypes.STRING,
        allowNull: false
      },
      semester: {
        type: DataTypes.STRING,
        allowNull: false
      },
      acadYear: {
        type: DataTypes.STRING,
        allowNull: false
      }

    }, {
      tableName: 'Activity' // Explicitly specify table name if different
    });

    /**
     * Relationship
     */
    Activity.associate = function(models) {
        Activity.hasMany(models.Attendance, { foreignKey: 'ActivityId' });
    };
  
    return Activity;
  };
  