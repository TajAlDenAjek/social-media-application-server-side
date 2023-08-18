const path=require('path');
const { StatusCodes } = require('http-status-codes')
const {User,Post,Comment,Reaction}=require(path.join(__dirname,'..','models'));
const Sequelize=require('sequelize');


const createPost=async(req,res)=>
{
    let data={};
    data.text=null;
    data.picture=null;
    let defaultState='public';
    if(req.body.data){
        const {text}= JSON.parse(req.body.data);
        data.text=text;
    }
    if(req.file){
        data.picture=req.file.filename;
    }
    data.userId=Number(req.user.id);
    const post= await Post.create({
        userId:data.userId,
        text:data.text,
        state:defaultState,
        picture:data.picture
    });
    res.status(StatusCodes.CREATED).json(post.dataValues);
};

const editPost=async(req,res)=>
{
    let patchUpdate={};
    if(req.body.data)
    {
        const {text}= JSON.parse(req.body.data);
        patchUpdate.text=text;
    }
    if(req.file){
        patchUpdate.picture=req.file.filename;
    }
    await Post.update(patchUpdate, {where: {id:req.params.id}});
    const data=await Post.findOne({ where: { id: req.params.id },attributes:{exclude:['UserId']}});
    res.status(StatusCodes.OK).json(data.dataValues);
};

const deletePost=async(req,res)=>
{
    let postId=req.params.id;
    // delete comments
    
    // delete reactions 

    // delete post
    const result=await Post.destroy({ where: { id: postId }});
    res.status(StatusCodes.OK).json({msg:"post has been deleted"});
};

const getPostById=async(req,res)=>
{
    let defaultState='public';
    const post=await Post.findOne({
        include:[
            {
                model: User,
                attributes: ['id','username', 'picturePath']    
            },
            {
                model: Comment,
                attributes:{
                    exclude:['UserId','PostId']
                },
                include:{
                    model: User,
                    attributes:['id','username','picturePath']
                }
            },
            {
                model:Reaction,
                attributes:{
                    exclude:['UserId','PostId']
                },
                include:{
                    model:User,
                    attributes:['id','username','picturePath'],
                }
            }
        ],
        where:{
            id:req.params.id,
            state:defaultState
        },
        attributes:{
            include: [
                [
                    Sequelize.literal('(SELECT COUNT(*) FROM comments WHERE comments.postId = post.id)'), 'commentsCount'
                ],
                [
                    Sequelize.literal('(SELECT COUNT(*) FROM reactions WHERE reactions.postId = post.id AND state="like")'), 'likesCount'
                ],
                [
                    Sequelize.literal('(SELECT COUNT(*) FROM reactions WHERE reactions.postId = post.id AND state="dislike")'), 'dislikesCount'
                ]
            ],
            exclude:['UserId']
        },
    });
    res.status(StatusCodes.OK).json(post);
};

const getAllPosts=async(req,res)=>
{
    let defaultState='public';
    const posts=await Post.findAll({
        include:[
            {
                model: User,
                attributes: ['id','username', 'picturePath']    
            },
            {
                model: Comment,
                attributes:{
                    exclude:['UserId','PostId']
                },
                include:{
                    model: User,
                    attributes:['id','username','picturePath']
                }
            },
            {
                model:Reaction,
                attributes:{
                    exclude:['UserId','PostId']
                },
                include:{
                    model:User,
                    attributes:['id','username','picturePath'],
                }
            }
        ],
        where:{
            userId:req.params.id,
            state:defaultState
        },
        attributes:{
            include: [
                [
                    Sequelize.literal('(SELECT COUNT(*) FROM comments WHERE comments.postId = post.id)'), 'commentsCount'
                ],
                [
                    Sequelize.literal('(SELECT COUNT(*) FROM reactions WHERE reactions.postId = post.id AND state="like")'), 'likesCount'
                ],
                [
                    Sequelize.literal('(SELECT COUNT(*) FROM reactions WHERE reactions.postId = post.id AND state="dislike")'), 'dislikesCount'
                ]
            ],
            exclude:['UserId']
        },
        order: [
            ['updatedAt', 'DESC'],
        ],
    });
    res.status(StatusCodes.OK).json(posts);
};

const postController={
    createPost,
    editPost,
    deletePost,
    getPostById,
    getAllPosts
};
module.exports=postController;


