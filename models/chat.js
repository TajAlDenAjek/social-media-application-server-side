'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class Chat extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      models.User.belongsToMany(models.User, { as: 'senderUser', through: Chat, foreignKey: 'senderUserId' ,otherKey: 'reciverUserId'});
      models.User.belongsToMany(models.User, { as: 'reciverUser', through:Chat, foreignKey: 'reciverUserId' ,otherKey: 'senderUserId'});
      Chat.belongsTo(models.User, { as: 'senderUser', onDelete: 'CASCADE'});
      Chat.belongsTo(models.User, { as: 'reciverUser', onDelete: 'CASCADE' });
    }
  }
  Chat.init({
    id:{
      type:DataTypes.INTEGER,
      allowNull:false,
      primaryKey:true,
      autoIncrement:true
    },
    message: DataTypes.STRING,
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
    modelName: 'Chat',
  });
  return Chat;
};