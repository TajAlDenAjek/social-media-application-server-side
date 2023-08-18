const path=require('path');
const authValidation=require(path.join(__dirname,'authentication'));
const userValidation=require(path.join(__dirname,'user'));
const postValidation=require(path.join(__dirname,'post'));
const commentValidation=require(path.join(__dirname,'comment'));
const reactionValidation=require(path.join(__dirname,'reaction'));
const relationshipValidation=require(path.join(__dirname,'relationship'));
const groupValidation=require(path.join(__dirname ,'group.js')) ;
module.exports=
{
    authValidation,
    userValidation,
    postValidation,
    commentValidation,
    reactionValidation,
    relationshipValidation,
    groupValidation
};