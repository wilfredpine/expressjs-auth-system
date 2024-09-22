module.exports = (sequelize, DataTypes) => {
  
    const Student = sequelize.define('Student', {
      firstName: {
        type: DataTypes.STRING,
        allowNull: false
      },
      middleName: {
        type: DataTypes.STRING,
        allowNull: true
      },
      lastName: {
        type: DataTypes.STRING
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
      },
      idNumber: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
      },
      rfId: {
        type: DataTypes.INTEGER,
        allowNull: true,
      },
      photoUrl: {
        type: DataTypes.STRING,
        allowNull: true
      },
      yearLevel: {
        type: DataTypes.INTEGER,
        allowNull: true
      },
      section: {
        type: DataTypes.STRING,
        allowNull: true
      }
    }, {
      tableName: 'Student' // Explicitly specify table name if different
    });
  
    /**
     * Relationships
     * @param {*} models 
     */
    Student.associate = function(models) {
      Student.hasMany(models.Attendance, { foreignKey: 'StudentId' });
      Student.hasMany(models.Enrolled, { foreignKey: 'StudentId' });
    };
  
    return Student;
  };
  
  