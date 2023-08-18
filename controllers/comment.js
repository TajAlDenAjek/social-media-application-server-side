const path=require('path');
const { StatusCodes } = require('http-status-codes')
const {User,Comment,Post}=require(path.join(__dirname,'..','models'));


const createComment=async(req,res)=>
{
    const comment=await Comment.create({
        userId:req.user.id,
        postId:req.params.id,
        text:req.body.text
    });
    res.status(StatusCodes.CREATED).json(comment.dataValues);
};

const editComment=async(req,res)=>
{
    let patchUpdate={};
    if(req.body){
        patchUpdate.text=req.body.text;
    }
    await Comment.update(patchUpdate, {where: {id:req.params.id}});
    const data=await Comment.findOne({ where: { id: req.params.id },attributes:{exclude:['UserId','PostId']}});
    res.status(StatusCodes.OK).json(data.dataValues);
};

const deleteComment=async(req,res)=>
{
    let commentId=req.params.id;
    // delete comment
    const result=await Comment.destroy({ where: { id: commentId }});
    res.status(StatusCodes.OK).json({msg:"comment has been deleted"});
};

const getCommentById=async(req,res)=>
{
    let defaultState='public';
    if(req.params.groupId){
        defaultState='private';
    }
    const comment=await Comment.findOne({
        include:[
            {
                model: User,
                attributes: ['id','username', 'picturePath']
            },
            {
                model: Post,
                attributes: [],
                where: {
                    state: defaultState
                }
            }
        ],
        where:{
            id:req.params.id
        },
        attributes:{
            exclude:['UserId','PostId']
        }
    });
    res.status(StatusCodes.OK).json(comment);
};

const getAllComments=async(req,res)=>
{
    const comments=await Comment.findAll({
        include:[
            {
                model: User,
                attributes: ['id','username', 'picturePath']
            },
            {
                model: Post,
                attributes: [],
                where: {
                    state: 'public'
                }
            }
        ],
        where:{
            userId:req.params.id
        },
        attributes:{
            exclude:['UserId','PostId'],
        },
        order: [
            ['updatedAt', 'DESC'],
        ],
    });
    res.status(StatusCodes.OK).json(comments);
};


const getAllCommentsForUserByPostId=async(req,res)=>
{
    const comments=await Comment.findAll({
        include:[
            {
                model: User,
                attributes: ['id','username', 'picturePath']
            },
            {
                model: Post,
                attributes: [],
                where: {
                    state: 'private'
                }
            }
        ],
        where:{
            userId:req.user.id,
            postId:req.params.id
        },
        attributes:{
            exclude:['UserId','PostId']
        }
    });
    res.status(StatusCodes.OK).json(comments);
};

const commentController={
    createComment,
    editComment,
    deleteComment,
    getCommentById,
    getAllComments,
    getAllCommentsForUserByPostId
};

module.exports=commentController;