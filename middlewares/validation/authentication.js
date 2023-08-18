const path=require('path');
const Validator=require('validatorjs');
const { StatusCodes } = require('http-status-codes');
const bcrypt = require('bcryptjs');
const { BadRequestError, UnauthenticatedError } = require(path.join(__dirname,'..','..','errors'));
const {User}=require(path.join(__dirname,'..','..','models'));


  
const register=async (req,res,next)=>
{ 
    const validationRule={
        username: "required",
        email: "required|email",
        password: "required|min:8|max:20",
    };
    let validation=new Validator(req.body,validationRule);
    const found = await User.findOne({
        where: {
            email: req.body.email,
        },
    });
    if(validation.passes()&&!found){
        return next();
    }
    if(found)
    {
        if(validation.errors.errors.email===undefined)
            validation.errors.errors.email=[];
        validation.errors.errors.email.push("Email is already in use !");
    }
    return res.status(StatusCodes.BAD_REQUEST).json(validation.errors.errors);
}
const login = async (req,res,next )=>{
    const validationRule = {
        "email":"required|email",
        "password":"required",
    };
    let validation = new Validator(req.body,validationRule);
    const {email,password} = req.body;
    const user=await User.findOne({where:{email:email}});
    let isPasswordCorrect=true;
    if(user)
        isPasswordCorrect = await bcrypt.compare(password, user.password);
    if(validation.passes()&&user&&isPasswordCorrect){
        return next();
    }
    let statusCode=StatusCodes.BAD_REQUEST;
    if(!user)
    {
        if(validation.errors.errors.email===undefined)
        {
            validation.errors.errors.email=[];
            validation.errors.errors.email.push("Invalid Credentials no such email");
            statusCode=StatusCodes.UNAUTHORIZED;
        }
    }
    if(!isPasswordCorrect)
    {
        if(validation.errors.errors.password===undefined)
        {
            validation.errors.errors.password=[];
            validation.errors.errors.password.push("Invalid Credentials Wrong Password");
            statusCode=StatusCodes.UNAUTHORIZED;
        }     
    }
    return res.status(statusCode).json(validation.errors.errors);
}
const authValidation={
    register,
    login
}

module.exports = authValidation;