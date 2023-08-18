const path=require('path');

const userAuth=require(path.join(__dirname,'user'));
const postAuth=require(path.join(__dirname,'post'));
const commentAuth=require(path.join(__dirname,'comment'));
const reactionAuth=require(path.join(__dirname,'reaction'));
const relationshipAuth=require(path.join(__dirname,'relationship'));
const groupAuth =require(path.join(__dirname,'group.js')) ;

module.exports={
    userAuth,
    postAuth,
    commentAuth,
    reactionAuth,
    relationshipAuth,
    groupAuth
    
}