const path=require('path');
const Validator=require('validatorjs');
const { StatusCodes } = require('http-status-codes');
const { BadRequestError, UnauthenticatedError } = require(path.join(__dirname,'..','..','errors'));
const {Comment}=require(path.join(__dirname,'..','..','models'));



const checkIdCommentExestence=async (req,res,next)=>
{
    let data={id:req.params.id};
    const validationRule={
        id: "required|numeric",
    };
    let validation=new Validator(data,validationRule);
    const found = await Comment.findOne({
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
            validation.errors.errors.comment=[];
            validation.errors.errors.comment.push("comment not found");
            statusCode=StatusCodes.OK;
        }
    }
    return res.status(statusCode).json(validation.errors.errors);
}

const commentData=async(req,res,next)=>
{
    let data=req.body;
    const validationRule={
        text:`required|string`,
    };
    let validation=new Validator(data,validationRule);
    if(validation.passes()){
        return next();
    }
    return res.status(StatusCodes.BAD_REQUEST).json(validation.errors.errors);
}

const commentValidation={
    checkIdCommentExestence,
    commentData
}
module.exports = commentValidation;