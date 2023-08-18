'use strict';
const { Model } = require('sequelize');


module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      User.hasMany(models.Post);
      User.hasMany(models.Comment);
      User.hasMany(models.Reaction);
      User.hasMany(models.GroupUser) ;
      User.belongsToMany(models.Group , {through: models.GroupUser });
      // User.hasMany(models.Chat);
      // User.hasMany(User,{ through: models.Relationship });
    }
  }
  User.init({
    id:{
      type:DataTypes.INTEGER,
      allowNull:false,
      primaryKey:true,
      autoIncrement:true
    },
    username: {
      type: DataTypes.STRING,
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
      type: DataTypes.STRING,
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
      type: DataTypes.STRING,
      allowNull:false,
    },
    firstName: {
      type: DataTypes.STRING
    },
    lastName: {
      type: DataTypes.STRING
    },
    picturePath: {
      type: DataTypes.STRING
    },
    gender: {
      type: DataTypes.STRING,
      validate:{
        isIn:[ ['male' , 'female']]
      }
    },
    birthday: {
      type: DataTypes.DATE
    },
    country: {
      type: DataTypes.STRING
    },
    socket_io_id: {
      type: DataTypes.STRING
    },
    refreshToken: {
      type: DataTypes.STRING
    },
    createdAt: {
      allowNull: false,
      type: DataTypes.DATE,
      defaultValue:DataTypes.NOW 
    },
    updatedAt: {
      allowNull: false,
      type: DataTypes.DATE,
      defaultValue:DataTypes.NOW
    },
  }, {
    sequelize,
    modelName: 'User',
  });
  return User;
};




