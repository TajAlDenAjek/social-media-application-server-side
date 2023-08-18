const path=require('path');
const express=require('express');
const router=express.Router();
const {chatController}=require(path.join(__dirname,'..','controllers'));
const {userValidation,relationshipValidation}=require(path.join(__dirname,'..','middlewares','validation'));
const {relationshipAuth}=require(path.join(__dirname,'..','middlewares','authorization'));



router.get('/messages/:id',
    userValidation.checkIdUserExestence,
    relationshipValidation.isItSelfLoop,
    relationshipAuth.isMyFriend,
    chatController.getMessages
);

module.exports = router;