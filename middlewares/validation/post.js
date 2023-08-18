const path=require('path');
const Validator=require('validatorjs');
const { StatusCodes } = require('http-status-codes');
const { BadRequestError, UnauthenticatedError } = require(path.join(__dirname,'..','..','errors'));
const {Post}=require(path.join(__dirname,'..','..','models'));



const checkIdPostExestence=async (req,res,next)=>
{
    let data={id:req.params.id};
    const validationRule={
        id: "required|numeric",
    };
    let validation=new Validator(data,validationRule);
    const found = await Post.findOne({
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
            validation.errors.errors.post=[];
            validation.errors.errors.post.push("post not found");
            statusCode=StatusCodes.OK;
        }
    }
    return res.status(statusCode).json(validation.errors.errors);
}

const postData=async(req,res,next)=>
{
    let data={};
    data.text=null;
    if(req.body.data){
        const {text}= JSON.parse(req.body.data);
        data.text=text;
    }
    const validationRule={
        text:`required|string`,
    };
    let validation=new Validator(data,validationRule);
    if(validation.passes()){
        return next();
    }
    return res.status(StatusCodes.BAD_REQUEST).json(validation.errors.errors);
}


const postValidation={
    checkIdPostExestence,
    postData
}
module.exports = postValidation;