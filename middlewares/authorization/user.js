const path=require('path');
const {unauthorized}=require(path.join(__dirname,'..','..','errors'));
const {User,Relationship}=require(path.join(__dirname,'..','..','models'));
const { Op } = require('sequelize');
const { isBlocker } = require('./relationship');



const accountOwnerShip=async(req,res,next)=>
{
    let authenticatedId=req.user.id;
    let requestedId=req.params.id;
    if(Number(authenticatedId)!==Number(requestedId))
        throw new unauthorized('You can only modify your account');
    return next();
};

const notBlocked=async(req,res,next)=>
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
                },
                {
                    firstUserId:secondUserId,
                    secondUserId:firstUserId,
                }
            ] 
        }
    });
    if(!found){
        req.state="Not Friends";
        return next();
    }
    if(found.dataValues.state==="blocked"){
        throw new unauthorized('this user is blocked');
    }
    req.state=found.dataValues.state;
    return next();
}

const userAuth={
    accountOwnerShip,
    notBlocked
}

module.exports=userAuth;