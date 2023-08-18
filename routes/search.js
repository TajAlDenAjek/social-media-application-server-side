const path=require('path');
const express=require('express');
const router=express.Router(); 
const {serachController} = require(path.join(__dirname , '..' , 'controllers')) ;


router.get('/groups' , serachController.searchForGroups) ;
router.get('/users' , serachController.searchForUsers) ;
router.get('/posts' , serachController.searchForPosts) ;
router.get('/comments' , serachController.searchForComments) ;

module.exports=router;