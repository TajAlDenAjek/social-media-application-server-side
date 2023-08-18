const path=require('path');
const {unauthorized}=require(path.join(__dirname,'..','..','errors'));
const {User,Post,Relationship,Reaction}=require(path.join(__dirname,'..','..','models'));
const { Op } = require('sequelize');


const reactionOwnerShip=async(req,res,next)=>
{
    let authenticatedId=req.user.id;
    let reactionId=req.params.id;
    let reactionOwnerId=await Reaction.findOne({where:{id:reactionId}});
    reactionOwnerId=reactionOwnerId.dataValues.userId;
    if(Number(authenticatedId)!==Number(reactionOwnerId))
        throw new unauthorized('You can only modify your reactions');
    return next();
};



const reactionOwnerIsMeOrMyFriend=async(req,res,next)=>
{
    let reactionId=Number(req.params.id);
    let reaction=await Reaction.findByPk(reactionId);
    reaction=reaction.dataValues;
    if(reaction.userId===req.user.id)
        return next();
    let firstUserId=req.user.id;
    let secondUserId=reaction.userId;
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
    throw new unauthorized("You can only see your reactions or your friends reactions or your groups reactions");
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
    throw new unauthorized("You can only see your reactions or your friends reactions or your groups reactions");
};


const onUpdateReactionAreFriends=async(req,res,next)=>
{
    let reactionId=Number(req.params.id);
    let reaction=await Reaction.findByPk(reactionId);
    reaction=reaction.dataValues;
    let postId=reaction.postId;
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
    throw new unauthorized("You can't update your reaction on post of user who is not your friend");
};


const reactionAuth={
    reactionOwnerShip,
    reactionOwnerIsMeOrMyFriend,
    userIsMeOrMyFriend,
    onUpdateReactionAreFriends
}

module.exports=reactionAuth;