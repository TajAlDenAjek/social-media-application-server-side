const path=require('path');
const Validator=require('validatorjs');
const { StatusCodes } = require('http-status-codes');
const bcrypt = require('bcryptjs');
const { BadRequestError, UnauthenticatedError } = require(path.join(__dirname,'..','..','errors'));
const {Post,Reaction}=require(path.join(__dirname,'..','..','models'));



const checkIdReactionExestence=async (req,res,next)=>
{
    let data={id:req.params.id};
    const validationRule={
        id: "required|numeric",
    };
    let validation=new Validator(data,validationRule);
    const found = await Reaction.findOne({
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
            validation.errors.errors.reaction=[];
            validation.errors.errors.reaction.push("Reaction not found");
            statusCode=StatusCodes.OK;
        }
    }
    return res.status(statusCode).json(validation.errors.errors);
}

const reactionData=async(req,res,next)=>
{
    let data=req.body;
    const expectedValues=['like','dislike'];
    const validationRule={
        state:`required|string|in:${expectedValues.join(',')}`,
    };
    let validation=new Validator(data,validationRule);
    if(validation.passes()){
        return next();
    }
    return res.status(StatusCodes.BAD_REQUEST).json(validation.errors.errors);
}

const reactOnceOnly=async(req,res,next)=>
{
    const found=await Reaction.findOne({
        where:{
            userId:req.user.id,
            postId:req.params.id
        }
    });
    if(!found)
        return next();
    let validation={};
    let statusCode=StatusCodes.CONFLICT;
    validation.reaction=[];
    validation.reaction.push("you have already reacted to this post");
    return res.status(statusCode).json(validation);
}

const reactionValidation={
    checkIdReactionExestence,
    reactionData,
    reactOnceOnly
}
module.exports = reactionValidation;