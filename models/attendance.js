module.exports = (sequelize, DataTypes) => {
    const Attendance = sequelize.define('Attendance', {
      date: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
        allowNull: false
      },
      StudentId: {
        type: DataTypes.INTEGER,
        references: {
          model: 'Student',
          key: 'id',
        },
        allowNull: false,
      },
      ActivityId: {
        type: DataTypes.INTEGER,
        references: {
          model: 'Activity',
          key: 'id',
        },
        allowNull: false,
      },
      yearLevel: {
        type: DataTypes.INTEGER, 
        allowNull: true,
      },
      section: {
        type: DataTypes.STRING, 
        allowNull: true,
      },

    }, {
      tableName: 'Attendance' // Explicitly specify table name if different
    });

    /**
     * Relationship
     * @param {*} models 
     */
    Attendance.associate = function(models) {
      Attendance.belongsTo(models.Student, { foreignKey: 'StudentId' });
      Attendance.belongsTo(models.Activity, { foreignKey: 'ActivityId' });
    };

    /**
     * Before creating attendace, check the student table's yearLevel and section to auto populate yearLevel and section of attendance table
     */
    Attendance.beforeCreate(async (attendance, options) => {
      const student = await sequelize.models.Student.findOne({
        where: { id: attendance.StudentId }, 
        attributes: ['yearLevel', 'section'],
      });
      
      if (student) {
        attendance.yearLevel = student.yearLevel;
        attendance.section = student.section;
      }
    });
  
    return Attendance;
  };
  