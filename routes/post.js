const path=require('path');
const express=require('express');
const router=express.Router();
const {postController}=require(path.join(__dirname,'..','controllers'));
const {userValidation,postValidation}=require(path.join(__dirname,'..','middlewares','validation'));
const {postAuth}=require(path.join(__dirname,'..','middlewares','authorization'));
const uploadImage=require(path.join(__dirname,'..','middlewares','uploadImage'));


router.post('/create',
    uploadImage,
    postValidation.postData,
    postController.createPost
);

router.patch('/edit/:id',
    postValidation.checkIdPostExestence,
    postAuth.postOwnerShip,
    uploadImage,
    postValidation.postData,
    postController.editPost
);
router.delete('/delete/:id',
    postValidation.checkIdPostExestence,
    postAuth.postOwnerShip,
    postController.deletePost
);


router.get('/:id',
    postValidation.checkIdPostExestence,
    postAuth.postOwnerIsMeOrMyFriend,
    postController.getPostById
);

router.get('/all/:id',
    userValidation.checkIdUserExestence,
    postAuth.userIsMeOrMyFriend,
    postController.getAllPosts
);

module.exports = router;