const path = require("path");
const express = require("express");

const router = express.Router();


// const {}=require(path.join(__dirname,'..','middlewares','validation'));
const {
  groupController,
  commentController,
  reactionController,
} = require(path.join(__dirname, "..", "controllers"));
const { groupAuth } = require(path.join(
  __dirname,
  "..",
  "middlewares",
  "authorization"
));
const uploadImage = require(path.join(
  __dirname,
  "..",
  "middlewares",
  "uploadImage.js"
));
const postMiddleware = require(path.join(
  __dirname,
  "..",
  "middlewares",
  "authorization",
  "post.js"
));
const { groupValidation  , reactionValidation } = require(path.join(
  __dirname,
  "..",
  "middlewares",
  "validation"
));

router.post("/", groupValidation.checkGroupData , uploadImage , groupController.createGroup);
router.get("/my", groupController.MyGroups);
router.post(
  "/:groupId/join",
  groupValidation.checkForGroupExistance,
  groupController.joinRequest
);
router.get(
  "/:groupId/members",
  groupValidation.checkForGroupExistance,
  groupController.groupMemebers
);
router.get(
  "/:groupId",
  groupValidation.checkForGroupExistance,
  groupController.getGroup
);

// Posts
// need to be group member
router.post(
  "/:groupId/post",
  [groupValidation.checkForGroupExistance, groupValidation.checkPostData , groupAuth.groupMember, uploadImage],
  groupController.createPost
);

router.get(
  "/:groupId/post",
  groupValidation.checkForGroupExistance,
  groupAuth.groupMember,
  groupController.getPosts
);
router.delete(
  "/:groupId/post/:postId",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForPostExistance,
  groupAuth.groupMember,
  groupAuth.postOwnerOrAdmin,
  groupController.deletePost
);
router.patch(
  "/:groupId/post/:postId",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForPostExistance,
  groupAuth.groupMember,
  groupAuth.postOwner,
  groupController.editPost
);
router.get(
  "/:groupId/post/:postId",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForPostExistance,
  groupAuth.groupMember,
  groupController.getPost
);

// comments
// id for post
router.post(
  "/:groupId/comment/:id",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForPostExistance,
  groupValidation.checkPostData,
  groupAuth.groupMember,
  commentController.createComment
);
router.patch(
  "/:groupId/comment/:id",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForCommentExistance,
  groupValidation.checkPostData,
  groupAuth.groupMember,
  groupAuth.commentOwner,
  commentController.editComment
);
router.delete(
  "/:groupId/comment/:id",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForCommentExistance,
  groupAuth.groupMember,
  groupAuth.commentOwnerOrAdmin,
  commentController.deleteComment
);
router.get(
  "/:groupId/comment/:id",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForCommentExistance,
  groupAuth.groupMember,
  commentController.getCommentById
);
// id for post
router.get(
  "/:groupId/comment/all/:id",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForPostExistance,
  groupAuth.groupMember,
  commentController.getAllCommentsForUserByPostId
);

// reaction
// id for post
router.post(
  "/:groupId/reaction/:id",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForPostExistance,
  groupAuth.groupMember,
  reactionValidation.reactOnceOnly ,
  reactionValidation.reactionData,
  reactionController.createReaction
);
router.patch(
  "/:groupId/reaction/:id",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForReactionExistance,
  groupAuth.groupMember,
  groupAuth.reactionOwner,
  reactionValidation.reactionData,
  reactionController.editReaction
);
router.delete(
  "/:groupId/reaction/:id",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForReactionExistance,
  groupAuth.groupMember,
  groupAuth.reactionOwnerOrAdmin,
  reactionController.deleteReaction
);
router.get(
  "/:groupId/reaction/:id",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForReactionExistance,
  groupAuth.groupMember,
  reactionController.getReactionById
);
// id for post
router.get(
  "/:groupId/reaction/all/:id",
  groupValidation.checkForGroupExistance,
  groupValidation.checkForPostExistance,
  groupAuth.groupMember,
  reactionController.getAllReactionsForUserByPostId
);

// need admin privliages
router.delete(
  "/:groupId",
  groupValidation.checkForGroupExistance,
  groupAuth.groupAdmin,
  groupController.deleteGroup
);
router.patch(
  "/:groupId",
  groupValidation.checkForGroupExistance,
  groupAuth.groupAdmin,
  groupValidation.checkGroupData,
  groupController.editGroup
);
router.get(
  "/:groupId/join",
  groupValidation.checkForGroupExistance,
  groupAuth.groupAdmin,
  groupController.showJoinRequests
);
router.post(
  "/:groupId/modifyRole/:userId/",
  groupValidation.checkForGroupExistance,
  groupValidation.checkUserExistanceInGroup,
  groupAuth.groupAdmin,
  groupValidation.checkModifyRole,
  groupController.modifyRole
);

module.exports = router;
