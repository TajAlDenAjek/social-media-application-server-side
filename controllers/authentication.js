const path=require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { StatusCodes } = require('http-status-codes');
const {User}=require(path.join(__dirname,'..','models'));


const register=async (req,res)=>
{
    const salt = await bcrypt.genSalt(10);
    req.body.password = await bcrypt.hash(req.body.password, salt);
    const user= await User.create({username:req.body.username,email:req.body.email,password:req.body.password});
    res.status(StatusCodes.CREATED).json({msg:"created successfully"});
}


const login=async (req,res)=>
{
    const {email} = req.body;
    const user=await User.findOne({where:{email:email}});
    const accessToken=jwt.sign(
        { id: user.id, username: user.username },
        process.env.ACCESS_TOKEN_SECRET,
        {
          expiresIn: process.env.ACCESS_TOKEN_JWT_LIFETIME,
        }
    );
    let refreshToken=jwt.sign(
        {id:user.id,username:user.username},
        process.env.REFRESH_TOKEN_SECRET,
        { 
            expiresIn:process.env.REFRESH_TOKEN_JWT_LIFETIME,
        }
    );
    refreshToken=accessToken;
    const result=await User.update({refreshToken:refreshToken},{where:{id:user.id}});
    res.status(StatusCodes.OK).json({ user: {id:user.id ,username: user.username } , token:accessToken });
}

const logout=async(req,res)=>
{
    const result=await User.update({refreshToken:null},{where:{id:req.user.id}});
    res.sendStatus(StatusCodes.NO_CONTENT);
}

const authController={register,login,logout};
module.exports=authController;