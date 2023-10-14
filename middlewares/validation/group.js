const path=require('path');
const Validator=require('validatorjs');
const { StatusCodes } = require('http-status-codes');
const { BadRequestError, UnauthenticatedError } = require(path.join(__dirname,'..','..','errors'));
const {Group, User, Post , Comment , Reaction , GroupUser ,GroupPost } = require(path.join(__dirname , '..', '..' ,'models')); 

// Validator.registerAsync('groupExists',  (groupId, attribute, req, passes)=> {
//     console.log(groupId , attribute , req , passes) ;
//     Group.findOne({where:{id:groupId}} , ) ;
//     if(!group){
//        passes(false, 'Group Not Found'); 
//        return ;
//     }
//     passes(); 
// }, 'the :attribute is not found.');
Validator.registerAsync('groupExists', async (value, attribute, req, passes) => {
    const group = await Group.findOne({where:{id : value }}); // Assuming email is the unique identifier for the user in your database
    if (group) {
        passes();
    } 
    else {
        passes(false, 'group not found');
    }
    return ;
});

Validator.registerAsync('postExists' , async (value , attribute , req ,passes )=>{
    const post = await GroupPost.findOne({where:{postId:value} });
    if(post){
        passes() ; 
    }
    else{
        passes(false,'post ont found') ;
    }
return ;
});
Validator.registerAsync('commentExists' , async (value , attribute , req ,passes )=>{
    const comment = await Comment.findOne({where:{id:value}}) ; 
    if(comment){
        passes() ; 
    }
    else{
        passes(false,'comment ont found') ;
    }
return ;
});
Validator.registerAsync('reactionExists' , async (value , attribute , req ,passes )=>{
    const reaction = await Reaction.findOne({where:{id:value}}) ; 
    if(reaction){
        passes() ; 
    }
    else{
        passes(false,'reaction ont found') ;
    }
return ;
});
Validator.registerAsync('userExists' , async (value , attribute , req , passes )=>{
    const user = await User.findOne({where:{id:value}}) ; 
    if(user){
        passes();
    }
    else{
        passes(false,'user not found') ; 
    }
});
Validator.registerAsync('groupPostExists' , async (value , attribute , req , passes )=>{
    const groupPost = await GroupPost.findOne({where:{id:value}}) ; 
    if(groupPost){
        passes();
    }
    else{
        passes(false,'post not found') ; 
    }
});
const checkGroupData = async (req, res , next)=>{
    let groupData={};
    
    if(req.body.data)
    {
        const data = JSON.parse(req.body.data);
        groupData=data;
    }
    let validationRule = {
        groupName:'required|string',
        groupDescription:'required|string'
    };
    let validator = new Validator(groupData,validationRule) ;
    if(validator.passes()){
        return next() ; 
    }
    return res.status(400).json({msg:'failed' , errors:validator.errors.errors});
}
const checkPostData = async (req,res,next)=>{
    let validationRule = {
        text:'required|string',
        // image: 'image...
    };
    let validator = new Validator(req.body, validationRule); 
    if(validator.passes()){
        return next() ; 
    }
    return res.status(400).json({msg:'failed' , errors:validator.errors.errors}) ; 
}
const checkForGroupPostExistance = async (req,res,next)=>{
    let data = {
        postId:req.params.id 
    };
    let validationRule={
        postId:'required|numeric|groupPostExists'
    };
    let validator = new Validator(data , validationRule) ;
    await validator.checkAsync(()=>{
         next() ;
    } , ()=>{
        return res.status(404).json({msg:'failed' , errors:validator.errors.errors}) ;
    });
};

const checkForGroupExistance = async (req,res,next)=>{
    
    let data = {
        groupId:(req.params.groupId||req.params.id)
    };
    let validationRule = {
        groupId:'required|numeric|groupExists'
    }; 
    let validator = new Validator(data , validationRule) ;
    await validator.checkAsync(()=>{
         next() ;
    } , ()=>{
        return res.status(404).json({msg:'failed' , errors:validator.errors.errors}) ;
    });
}
const checkForPostExistance = async (req,res,next)=>{
    
    let data = {
        postId:(req.params.id || req.params.postId)
    };
    let validationRule = {
        postId: 'required|numeric|postExists'
    };
    let validator = new Validator(data , validationRule) ;
    
    await validator.checkAsync(()=>{
         next() ;
    } , ()=>{
        return res.status(404).json({msg:'failed' , errors:validator.errors.errors}) ;
    });    
};

const checkForCommentExistance = async (req,res,next)=>{
    let data = {
        commentId:req.params.id 
    };
    let validationRule = {
        commentId: 'required|numeric|commentExists'
    };
    let validator = new Validator(data , validationRule) ;
    await validator.checkAsync(()=>{
         next() ;
    } , ()=>{
        return res.status(404).json({msg:'failed' , errors:validator.errors.errors}) ;
    });    
};

const checkForReactionExistance = async (req,res,next)=>{
    let data = {
        reactionId:req.params.id
    };
    let validationRule = {
        reactionId: 'required|numeric|reactionExists'
    };
    let validator = new Validator(data , validationRule) ;
    await validator.checkAsync(()=>{
         next() ;
    } , ()=>{
        return res.status(404).json({msg:'failed' , errors:validator.errors.errors}) ;
    });    
};
const checkForUserExistance = async (req, res,next)=>{
     let data = {
        userId: req.params.id 
     };
     let validationRule = {
        userId: 'required|numeric|userExists'
     };
     let  validator = new Validator(data , validationRule) ;
     await validator.checkAsync( ()=>{
        next() ;
     } , ()=>{
        return res.status(404).json({msg:'failed' , errors:validator.errors.errors}) ;
     })
};
const checkUserExistanceInGroup = async (req ,res ,next)=>{
    let groupUser = await GroupUser.findOne({where:{groupId:req.params.groupId , userId: req.params.userId}}) ;
    if(!groupUser){
        return res.status(404).json({msg:'user not found'} ) ;
    }
    return next() ;
}
const checkModifyRole = async (req, res, next)=>{
    let states = ['kicked' ,'normal', 'Admin' ] ;
    let validationRule = {
        state:`required|in:${states.join(',')}`
    };
    let validator = new Validator(req.body , validationRule) ;
    if(validator.passes()){
        return next() ; 
    }
    return res.status(400).json({msg:'failed' , errors: validator.errors.errors});
}
let groupValidation ={
    checkGroupData ,
    checkForGroupExistance,
    checkUserExistanceInGroup,
    checkModifyRole,
    checkPostData,
    checkForCommentExistance,
    checkForPostExistance,
    checkForReactionExistance,
    checkForUserExistance,
    checkForGroupPostExistance
};
module.exports = groupValidation ; 