const path=require('path');
const {unauthorized}=require(path.join(__dirname,'..','..','errors'));
const {User,Post,Relationship,Comment}=require(path.join(__dirname,'..','..','models'));
const { Op } = require('sequelize');



const commentOwnerShip=async(req,res,next)=>
{
    let authenticatedId=req.user.id;
    let commentId=req.params.id;
    let commentOwnerId=await Comment.findOne({where:{id:commentId}});
    commentOwnerId=commentOwnerId.dataValues.userId;
    if(Number(authenticatedId)!==Number(commentOwnerId))
        throw new unauthorized('You can only modify your comments');
    return next();
};

const commentOwnerIsMeOrMyFriend=async(req,res,next)=>
{
    let commentId=Number(req.params.id);
    let comment=await Comment.findByPk(commentId);
    comment=comment.dataValues;
    if(comment.userId===req.user.id)
        return next();
    let firstUserId=req.user.id;
    let secondUserId=comment.userId;
    const found=await Relationship.findOne({
        where:{
            [Op.or]: [
                {
                    firstUserId:firstUserId,
                    secondUserId:secondUserId,
                    state:"friends"
                },
                {
                    firstUserId:secondUserId,
                    secondUserId:firstUserId,
                    state:"friends"
                }
            ] 
        }
    });
    if(found)
        return next();
    throw new unauthorized("You can only see your comments or your friends comments or your groups comments");
};


const userIsMeOrMyFriend=async(req,res,next)=>
{
    let firstUserId=req.user.id;
    let secondUserId=req.params.id;
    if(Number(firstUserId)===Number(secondUserId))
        return next();
    const found=await Relationship.findOne({
        where:{
            [Op.or]: [
                {
                    firstUserId:firstUserId,
                    secondUserId:secondUserId,
                    state:"friends"
                },
                {
                    firstUserId:secondUserId,
                    secondUserId:firstUserId,
                    state:"friends"
                }
            ] 
        }
    });
    if(found)
        return next();
    throw new unauthorized("You can only see your comments or your friends comments or your groups comments");
};


const onUpdateCommentAreFriends=async(req,res,next)=>
{
    let commentId=Number(req.params.id);
    let comment=await Comment.findByPk(commentId);
    comment=comment.dataValues;
    let postId=comment.postId;
    let post=await Post.findByPk(postId);
    post=post.dataValues;
    let firstUserId=req.user.id;
    let secondUserId=post.userId;
    if(Number(firstUserId)===Number(secondUserId))
        return next();
    const found=await Relationship.findOne({
        where:{
            [Op.or]: [
                {
                    firstUserId:firstUserId,
                    secondUserId:secondUserId,
                    state:"friends"
                },
                {
                    firstUserId:secondUserId,
                    secondUserId:firstUserId,
                    state:"friends"
                }
            ] 
        }
    });
    if(found)
        return next();
    throw new unauthorized("You can't update your comment on post of user who is not your friend");
};


const commentAuth={
    commentOwnerShip,
    commentOwnerIsMeOrMyFriend,
    userIsMeOrMyFriend,
    onUpdateCommentAreFriends
}

module.exports=commentAuth;