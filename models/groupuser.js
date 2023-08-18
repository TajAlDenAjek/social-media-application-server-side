'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class GroupUser extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      GroupUser.belongsTo(models.User, { foreignKey: 'userId' });
      GroupUser.belongsTo(models.Group, { foreignKey: 'groupId' });
      GroupUser.hasMany(models.GroupPost);
    }
  }
  GroupUser.init({
    id:{
      type:DataTypes.INTEGER,
      allowNull:false,
      primaryKey:true,
      autoIncrement:true
    },
    groupId:{
      type:DataTypes.INTEGER ,
      references:{
        table:'groups' ,
        key:'id'
      }
    },
    userId:{
      type:DataTypes.INTEGER ,
      references:{
        table:'users' ,
        key:'id'
      }
    },
    state: {
      type: DataTypes.STRING,
      validate:{
        isIn:[ ['Owner','Admin','normal','pending','kicked']]
      }
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
    modelName: 'GroupUser',
  });
  return GroupUser;
};