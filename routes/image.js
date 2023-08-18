const path = require('path') ; 
const express = require('express') ; 
const router = express.Router() ; 
const {imageController} = require(path.join(__dirname  , '..' , 'controllers' )) ;
const {groupValidation} = require(path.join(__dirname , '..','middlewares' ,'validation'));

router.get('/profile/:id', groupValidation.checkForUserExistance , imageController.getProfilePhoto )  ;
router.get('/group/:id' , groupValidation.checkForGroupExistance, imageController.getGroupPhoto ); 
router.get('/post/:id'  ,  groupValidation.checkForPostExistance,imageController.getPostPhoto) ; 
router.get('/groupPost/:id' , groupValidation.checkForGroupPostExistance ,imageController.getGroupPostPhoto ) ;


module.exports = router ;