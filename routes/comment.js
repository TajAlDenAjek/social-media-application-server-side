const path=require('path');
const express=require('express');
const router=express.Router();
const {commentController}=require(path.join(__dirname,'..','controllers'));
const {userValidation,postValidation,commentValidation}=require(path.join(__dirname,'..','middlewares','validation'));
const {postAuth,commentAuth}=require(path.join(__dirname,'..','middlewares','authorization'));



router.post('/add/:id',
    postValidation.checkIdPostExestence,
    postAuth.postIsPublic,
    postAuth.postOwnerIsMeOrMyFriend,
    commentValidation.commentData,
    commentController.createComment
);
router.patch('/edit/:id',
    commentValidation.checkIdCommentExestence,
    commentAuth.commentOwnerShip,
    commentAuth.onUpdateCommentAreFriends,
    commentValidation.commentData,
    commentController.editComment
);
router.delete('/delete/:id',
    commentValidation.checkIdCommentExestence,
    commentAuth.commentOwnerShip,
    commentController.deleteComment
);

router.get('/:id',
    commentValidation.checkIdCommentExestence,
    commentAuth.commentOwnerIsMeOrMyFriend,
    commentController.getCommentById
);

router.get('/all/:id',
    userValidation.checkIdUserExestence,
    commentAuth.userIsMeOrMyFriend,
    commentController.getAllComments
);

module.exports=router;