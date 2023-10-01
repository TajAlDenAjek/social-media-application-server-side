const path=require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { StatusCodes } = require('http-status-codes')
const {User}=require(path.join(__dirname,'..','models'));

const getUser=async(req,res)=>
{
    const user=await User.findOne({
        where:{
            id:req.params.id
        },
        attributes:{
            exclude:['password','socket_io_id','refreshToken']
        }
    });
    if(req.state)
        user.dataValues.state=req.state;
    res.status(StatusCodes.OK).json(user);
};

const updateUser=async(req,res)=>
{
    let patchUpdate={};
    if(req.body.data)
    {
        const { id,email,picturePath,createdAt,updatedAt,refreshToken,socket_io_id, ...data } = JSON.parse(req.body.data);
        patchUpdate=data;
    }
    if(req.file){
        patchUpdate.picturePath=req.file.filename;
    }
    if(patchUpdate.password){
        const salt = await bcrypt.genSalt(10);
        patchUpdate.password = await bcrypt.hash(patchUpdate.password, salt);
        // patchUpdate.refreshToken="reloginRequired";
    }
    const result = await User.update(patchUpdate, {where: {id:req.params.id}});
    res.status(StatusCodes.OK).json({msg:"updated successfully"});
};

const deleteUser=async(req,res)=>
{
    let userId=req.params.id;
    // delete posts 
    
    // delete comments
    
    // delete reactions 

    // delete groups posts inside comments reactions 

    // delete friends and messages

    // delete profile
    const result=await User.destroy({ where: { id: userId }});
    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
    res.status(StatusCodes.OK).json({msg:"account has been deleted"});
};


const userController={
    getUser,
    updateUser,
    deleteUser,
};
module.exports=userController;