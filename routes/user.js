const path=require('path');
const express=require('express');
const router=express.Router();
const {userController}=require(path.join(__dirname,'..','controllers'));
const {userValidation}=require(path.join(__dirname,'..','middlewares','validation'));
const uploadImage=require(path.join(__dirname,'..','middlewares','uploadImage'));
const {userAuth}=require(path.join(__dirname,'..','middlewares','authorization'));


router.get('/profile/:id',
    userValidation.checkIdUserExestence,
    userAuth.notBlocked,
    userController.getUser
);
router.patch('/profile/:id',
    userValidation.checkIdUserExestence,
    userAuth.accountOwnerShip,
    uploadImage,
    userValidation.updateProfileOfUser,
    userController.updateUser
);


router.delete('/profile/:id',
    userValidation.checkIdUserExestence,
    userAuth.accountOwnerShip,
    userController.deleteUser
);




module.exports = router;