'use strict';
/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('Users', {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: Sequelize.INTEGER
      },
      username: {
        type: Sequelize.STRING,
        allowNull:false,
        validate: {
          notNull: {
            msg: 'Please enter your username'
          },
          customValidator(username) {
            if (username === "") {
              throw new Error("name can't be empty Please enter your username");
            }
          },
        }
      },
      email: {
        type: Sequelize.STRING,
        allowNull:false,
        unique: {
          args: true,
          msg: 'Email address already in use!'
        },
        validate:{
          isEmail:true
        }
      },
      password: {
        type: Sequelize.STRING,
        allowNull:false,
      },
      firstName: {
        type: Sequelize.STRING
      },
      lastName: {
        type: Sequelize.STRING
      },
      picturePath: {
        type: Sequelize.STRING
      },
      gender: {
        type: Sequelize.STRING,
        validate:{
          isIn:[ ['male' , 'female']]
        }
      },
      birthday: {
        type: Sequelize.DATE
      },
      country: {
        type: Sequelize.STRING
      },
      socket_io_id: {
        type: Sequelize.STRING
      },
      refreshToken: {
        type: Sequelize.STRING
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue:Sequelize.NOW 
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue:Sequelize.NOW
      }
    });
  },
  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('Users');
  }
};