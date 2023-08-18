const path=require('path');
const {unauthorized}=require(path.join(__dirname,'..','..','errors'));
const {User,Post,Relationship}=require(path.join(__dirname,'..','..','models'));
const { Op } = require('sequelize');



const postOwnerShip=async(req,res,next)=>
{
    let authenticatedId=req.user.id;
    let postId=req.params.id;
    let postOwnerId=await Post.findOne({where:{id:postId}});
    postOwnerId=postOwnerId.dataValues.userId;
    if(Number(authenticatedId)!==Number(postOwnerId))
        throw new unauthorized('You can only modify your posts');
    return next();
};





const postOwnerIsMeOrMyFriend=async(req,res,next)=>
{
    let postId=Number(req.params.id);
    let post=await Post.findByPk(postId);
    post=post.dataValues;
    if(post.userId===req.user.id)
        return next();
    let firstUserId=req.user.id;
    let secondUserId=post.userId;
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
    throw new unauthorized("You can only see/interact your posts or your friends posts or your groups posts");
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
    throw new unauthorized("You can only see/(interact with )your posts or your friends posts or your groups posts");
};

const postIsPublic=async(req,res,next)=>
{
    let postId=Number(req.params.id);
    let post=await Post.findByPk(postId);
    if(post.dataValues.state==="public")
        return next();
    throw new unauthorized("You can only see/(interact with )your posts or your friends posts or your groups posts");
};

const postAuth={
    postOwnerShip,
    postOwnerIsMeOrMyFriend,
    userIsMeOrMyFriend,
    postIsPublic
}

module.exports=postAuth;