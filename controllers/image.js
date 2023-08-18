const path = require('path') ;
const {Group , GroupUser , User , Post , GroupPost , Reaction, Comment ,Sequelize , Relationship  }= require(path.join(__dirname , '..' , 'models'  )) ;
const { Op } = require('sequelize');


const getProfilePhoto = async (req, res )=>{
    const user = await User.findOne({where:{id : req.params.id}}) ; 
    if(!user.picturePath)
        return res.status(404).sendFile(path.join(__dirname ,'..','public','images','prototype.jpg'));
    return res.sendFile(path.join(__dirname , '..' ,'public' ,'images' , user.picturePath )) ; 
}

const getGroupPhoto = async (req , res )=>{
    const group = await Group.findOne({where:{id: req.params.id}}) ; 
    if(!group.groupPicture)
        return res.status(404).sendFile(path.join(__dirname ,'..','public','images','prototype.jpg'));
    return res.sendFile(path.join(__dirname , '..' ,'public' ,'images' , group.groupPicture)) ; 
}
const getPostPhoto = async (req, res )=>{
    const post = await Post.findOne({where:{id: req.params.id }}) ;
    const relationship = await Relationship.findOne({
        where:{
        [Op.or]:[
            {firstUserId:req.user.id , secondUserId: post.userId} ,
            {firstUserId:post.userId , secondUserId: req.user.id }
        ]
    }});
    if(!relationship){
        return res.status(403).json({msg:'You are not authroized to view this photo'});
    }
    if(!post.picturePath)
        return res.status(404).sendFile(path.join(__dirname ,'..','public','images','prototype.jpg'));
    return res.sendFile(path.join(__dirname ,'..','public','images',post.picturePath));
}
const getGroupPostPhoto = async (req , res )=>{
    const post = await GroupPost.findOne({where:{postId:req.params.id} });
    if(!post){ 
        let errors = {// temp
            postId:['post not found']
        };
        return res.status(404).json({msg:'failed' , errors});
    }
    const groupUser = await GroupUser.findOne({where:{groupId:post.groupId , userId: req.user.id }});
    if(!groupUser){
        return res.status(403).json({msg:'You are not authroized to view this photo'});
    }
    if(!post.picturePath)
        return res.status(404).sendFile(path.join(__dirname ,'..','public','images','prototype.jpg'));
    return res.sendFile(path.join(__dirname ,'..','public','images',post.picturePath));
}
const imageController = {
    getProfilePhoto,
    getGroupPhoto,
    getGroupPostPhoto,
    getPostPhoto
};
module.exports = imageController ;