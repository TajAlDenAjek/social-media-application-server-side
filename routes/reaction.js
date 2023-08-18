const path=require('path');
const express=require('express');
const router=express.Router();
const {reactionController}=require(path.join(__dirname,'..','controllers'));
const {userValidation,postValidation,reactionValidation}=require(path.join(__dirname,'..','middlewares','validation'));
const {postAuth,reactionAuth}=require(path.join(__dirname,'..','middlewares','authorization'));


router.post('/add/:id',
    postValidation.checkIdPostExestence,
    postAuth.postIsPublic,
    reactionValidation.reactOnceOnly,
    reactionValidation.reactionData,
    postAuth.postOwnerIsMeOrMyFriend,
    reactionController.createReaction
);

router.patch('/edit/:id',
    reactionValidation.checkIdReactionExestence,
    reactionAuth.reactionOwnerShip,
    reactionValidation.reactionData,
    reactionAuth.onUpdateReactionAreFriends,
    reactionController.editReaction  
);

router.delete('/delete/:id',
    reactionValidation.checkIdReactionExestence,
    reactionAuth.reactionOwnerShip,
    reactionController.deleteReaction
);


router.get('/:id',
    reactionValidation.checkIdReactionExestence,
    reactionAuth.reactionOwnerIsMeOrMyFriend,
    reactionController.getReactionById
);
router.get('/all/:id',
    userValidation.checkIdUserExestence,
    reactionAuth.userIsMeOrMyFriend,
    reactionController.getAllReactions
);

module.exports=router;