const path=require('path');
const {GroupUser , GroupPost , Post , Reaction , Comment }=require(path.join(__dirname,'..','..','models'));

const groupAdmin =async(req,res,next)=>
{
    let user = req.user; 
    let groupUser = await GroupUser.findOne({where:{userId:user.id , groupId: req.params.groupId }}) ;
    if(!groupUser){
        return res.status(404).json({msg:"Group Not found "});
    }
    if((groupUser.state != 'Admin' && groupUser.state != 'Owner')){
        return res.status(400).json({msg:"Forbidden Operation Not allowed"});
    }
    return next();
};

const groupMember =async(req,res,next)=>
{
    let user = req.user; 
    let groupUser = await GroupUser.findOne({where:{userId:user.id , groupId: (req.params.groupId||req.body.groupId) }}) ;
    if(!groupUser){
        return res.status(404).json({msg:"Group Not found "});
    }
    if((groupUser.state == 'pending' || groupUser.state == 'kicked')){
        return res.status(400).json({msg:"Forbidden Operation Not allowed"});
    }
    return next();
};

const postOwner = async ( req,res,next )=>{
    let groupUser = await GroupUser.findOne({where:{userId:req.user.id , groupId: req.params.groupId}}); 
    
    let groupPost = await GroupPost.findOne({where:{groupId: req.params.groupId , postId: req.params.postId, groupUserId:groupUser.id}});
    if(!groupPost){
        return res.status(404).json({msg:'Post Not found!'}) ;
    }
    if( groupUser.state == 'pending' || groupUser.state == 'kicked'){
        return res.status(400).json({msg:"Forbidden Operation Not allowed"});
    }
    next() ;
}
const postOwnerOrAdmin = async (req,res,next)=>{
    let groupUser = await GroupUser.findOne({where:{userId:req.user.id , groupId: req.params.groupId}}); 
    
    if(groupUser.state == 'Admin' || groupUser.state == 'Owner'){
        return next() ;
    }
    let groupPost = await GroupPost.findOne({where:{groupId: req.params.groupId , postId: req.params.postId, groupUserId:groupUser.id}});
    if(!groupPost){
        return res.status(404).json({msg:'Post Not found!'}) ;
    }
    if( groupUser.state == 'pending' || groupUser.state == 'kicked'){
        return res.status(400).json({msg:"Forbidden Operation Not allowed"});
    }
    next() ;
}

const commentOwner = async (req,res,next)=>{
    let comment = await Comment.findOne({where:{id:req.params.id, userId:req.user.id}}) ;
    if(!comment){
        return res.status(404).json({msg:'Forbidden Operation Not allowed'}) ; 
    }
    next();
}

const commentOwnerOrAdmin = async (req,res,next)=>{
    let groupUser = await GroupUser.findOne({where:{userId :  req.user.id , groupId: req.params.groupId}}) ;
    if(groupUser.state == 'Admin' || groupUser.state == 'Owner'){
        return next() ;
    }
    let comment = await Comment.findOne({where:{id:req.params.id, userId:req.user.id}}) ;
    if(!comment){
        return res.status(404).json({msg:'Forbidden Operation Not allowed'}) ; 
    }
    next();
}
const reactionOwner = async (req , res , next) =>{
    let reaction = await Reaction.findOne({where:{id:req.params.id , userId: req.user.id}}) ; 
    if(!reaction){
        return res.status(404).json({msg:'Forbidden Opeartion Not allowed'}) ; 
    }
    next() ;
}
const reactionOwnerOrAdmin = async (req, res,next)=>{
    let groupUser = await GroupUser.findOne({where:{userId :  req.user.id , groupId: req.params.groupId}}) ;
    if(groupUser.state == 'Admin' || groupUser.state == 'Owner'){
        return next() ;
    }
    let reaction = await Reaction.findOne({where:{id:req.params.id , userId: req.user.id}}) ; 
    if(!reaction){
        return res.status(404).json({msg:'Forbidden Opeartion Not allowed'}) ; 
    }
    next() ;
}

module.exports={
    groupAdmin ,
    groupMember,
    postOwner,
    postOwnerOrAdmin,
    commentOwner,
    commentOwnerOrAdmin,
    reactionOwner,
    reactionOwnerOrAdmin
};


