const path=require('path');
const {unauthorized}=require(path.join(__dirname,'..','..','errors'));
const {User,Relationship}=require(path.join(__dirname,'..','..','models'));
const { Op } = require('sequelize');

const isPartInTheRelation=async(req,res,next)=>
{
    let userId=req.user.id;
    let relationship=await Relationship.findByPk(req.params.id);
    relationship=relationship.dataValues;
    if(Number(userId)===Number(relationship.firstUserId)||Number(userId)===Number(relationship.secondUserId))
        return next();
    throw new unauthorized('You are not a part of the relation');
};

const isSender=async(req,res,next)=>
{
    let userId=req.user.id;
    let relationship=await Relationship.findByPk(req.params.id);
    relationship=relationship.dataValues;
    if(Number(userId)!==Number(relationship.firstUserId))
        throw new unauthorized('You are not the sender of the request');
    return next();
};

const isReceiver=async(req,res,next)=>
{
    let userId=req.user.id;
    let relationship=await Relationship.findByPk(req.params.id);
    relationship=relationship.dataValues;
    if(Number(userId)!==Number(relationship.secondUserId))
        throw new unauthorized('You are not the receiver of the request');
    return next();
};

const isMyFriend=async(req,res,next)=>
{
    let firstUserId=req.user.id;
    let secondUserId=req.params.id;
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
    throw new unauthorized('This is user is not your friend !!');
};

const isBlocker=async(req,res,next)=>
{
    if(Number(req.user.id)===Number(req.blockedRelationship.firstUserId))
        return next();
    throw new unauthorized(`You can't unblock someone who blocked you !!`);
}


const relationshipAuth={
    isPartInTheRelation,
    isSender,
    isReceiver,
    isMyFriend,
    isBlocker
}

module.exports=relationshipAuth;

