const path=require('path');
const Validator=require('validatorjs');
const { StatusCodes } = require('http-status-codes');
const bcrypt = require('bcryptjs');
const { BadRequestError, UnauthenticatedError } = require(path.join(__dirname,'..','..','errors'));
const {Relationship}=require(path.join(__dirname,'..','..','models'));
const { Op } = require('sequelize');


const checkIdRelationshipExestence=async (req,res,next)=>
{
    let data={id:req.params.id};
    const validationRule={
        id: "required|numeric",
    };
    let validation=new Validator(data,validationRule);
    const found = await Relationship.findOne({
        where: {
            id:data.id,
        },
    });
    let statusCode=StatusCodes.BAD_REQUEST;
    if(validation.passes()&&found){
        return next();
    }
    if(!found)
    {
        if(validation.errors.errors.id===undefined)
        {
            validation.errors.errors.relationship=[];
            validation.errors.errors.relationship.push("Relationship not found");
            statusCode=StatusCodes.OK;
        }
    }
    return res.status(statusCode).json(validation.errors.errors);
}

const relationshipData=async(req,res,next)=>
{
    let data=req.body;
    const expectedValues=['friends','blocked','pending','removed'];
    const validationRule={
        state:`required|string|in:${expectedValues.join(',')}`,
    };
    let validation=new Validator(data,validationRule);
    if(validation.passes()){
        return next();
    }
    return res.status(StatusCodes.BAD_REQUEST).json(validation.errors.errors);
}

const pendingRequestOrInRelation=async(req,res,next)=>
{
    let firstUserId=req.user.id;
    let secondUserId=req.params.id;
    // console.log(firstUserId);
    // console.log(secondUserId);
    //firstUserId  secondUserId
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
    if(!found)
        return next();
    let validation={};
    let statusCode=StatusCodes.CONFLICT;
    const { state, secondUserId: second, firstUserId: first } = found.dataValues;
    // console.log(state);
    // console.log(first);
    // console.log(second);
    let response="there is already a relationship.";

    if(state==="friends"){

        response="You are already friends.";

    }else if(state==="blocked"&&first===firstUserId){

        response="You blocked this user.";

    }else if(state==="blocked"&&second===firstUserId){

        response="This user has blocked you.";

    }else if(state==="pending"&&first===firstUserId){

        response="You have already sent a request to this user.";

    }else if(state==="pending"&&second===firstUserId){

        response="This user has sent you a request, Check received requests.";
    }
    validation.relationship=[];
    validation.relationship.push(response);
    return res.status(statusCode).json(validation);
}

const isItSelfLoop=async(req,res,next)=>
{
    let firstUserId=req.user.id;
    let secondUserId=req.params.id;
    if(firstUserId!=secondUserId)
        return next();
    let validation={};
    let statusCode=StatusCodes.BAD_REQUEST;
    validation.relationship=[];
    validation.relationship.push("No self loops in the friends system ,The given ID is the same as yours");
    return res.status(statusCode).json(validation);
};

const isPendingRequest=async(req,res,next)=>
{
    let relationship=await Relationship.findByPk(req.params.id);
    relationship=relationship.dataValues;
    if(relationship.state==="pending")
        return next();
    let validation={};
    let statusCode=StatusCodes.BAD_REQUEST;
    validation.relationship=[];
    validation.relationship.push("The request is not pending or recevied , you are friends or blocked ");
    return res.status(statusCode).json(validation);    
};

const AreFriends=async(req,res,next)=>
{
    let relationship=await Relationship.findByPk(req.params.id);
    relationship=relationship.dataValues;
    if(relationship.state==="friends")
        return next();
    let validation={};
    let statusCode=StatusCodes.BAD_REQUEST;
    validation.relationship=[];
    validation.relationship.push("You must be friends to do the action");
    return res.status(statusCode).json(validation);    
};

const AreBlocked=async(req,res,next)=>
{
    let firstUserId=req.user.id;
    let secondUserId=req.params.id;
    const found=await Relationship.findOne({
        where:{
            [Op.or]: [
                {
                    firstUserId:firstUserId,
                    secondUserId:secondUserId,
                    state:"blocked"
                },
                {
                    firstUserId:secondUserId,
                    secondUserId:firstUserId,
                    state:"blocked"
                }
            ] 
        }
    });
    if(found)
    {
        req.blockedRelationship=found.dataValues;
        return next();
    }
    let validation={};
    let statusCode=StatusCodes.BAD_REQUEST;
    validation.relationship=[];
    validation.relationship.push("there is no blocked relationship here");
    return res.status(statusCode).json(validation);    
};


const relationshipValidation={
    checkIdRelationshipExestence,
    relationshipData,
    pendingRequestOrInRelation,
    isItSelfLoop,
    isPendingRequest,
    AreFriends,
    AreBlocked,
}
module.exports = relationshipValidation;